-- =============================================================================
-- WAF forward-auth 鉴权脚本（OpenResty / Lua）
-- =============================================================================
--
-- 职责：在 access 阶段把当前请求送交 WAF 判定，并把 WAF 的结论转化为对外响应。
--
-- 相对原生 auth_request 的核心优势：
--   1) 可以把请求体随子请求一起送交 WAF（体检测的前提）；
--   2) 可以拿到 WAF 子请求的响应体，把 JSON 错误体直接回写给客户端，
--      不需要额外的 error_page 跳转。
--
-- 与 WAF 侧的契约（docs/forward-auth-design.md §3.4 / docs/configuration.md §2.3）：
--   放行：HTTP 2xx，无响应体；
--   拦截：WAF 通过 X-WAF-Code / X-WAF-Verdict / X-WAF-Rule-Id 等响应头表达真实语义，
--         本脚本据此还原对外状态码与错误体。
--
-- 为什么「原始请求信息」必须由本脚本显式注入（而不是依赖 $request_uri 等变量）：
--   ngx.location.capture 创建的是**子请求**，子请求的方法与 URI 属于子请求自身。
--   若在内部 location 里直接写 $request_uri / $request_method，拿到的是子请求的值
--   （/__waf_auth、POST），WAF 会把内部路径当成被保护的请求。
--   因此这里用 ngx.req.set_header 把原始信息写进**当前请求**的请求头
--   （子请求会继承父请求的 headers_in），由内部 location 原样透传。
--
-- 部署位置：/etc/waf/lua/waf_auth.lua（与 nginx.conf 中的 lua_package_path 保持一致）。
-- =============================================================================

local _M = {}

-- -----------------------------------------------------------------------------
-- 可调参数
-- -----------------------------------------------------------------------------

-- 单个请求最大随子请求转发的请求体字节数。
--
-- 超过该值时按「截断」处理：只转发前 N 字节，让 WAF 依然能看到请求体的头部内容
-- （绝大多数注入攻击特征位于请求体前部），从而避免把大文件上传整体读入内存。
-- 该值应与 WAF 侧 ingress.body.max_bytes 保持同量级。
local MAX_FORWARD_BODY_BYTES = 1024 * 1024

-- 鉴权通道不可用（子请求失败）时是否放过请求。
--
-- false = 失败关闭（fail-closed，默认）：宁可暂时阻断业务，也不放行不可检测的流量。
-- true  = 失败开放（fail-open）：可用性优先，但存在「WAF 故障期间无防护」的风险。
-- 该取舍与主流 forward-auth 方案（oauth2-proxy / Authelia）的默认策略一致。
local FAIL_OPEN = false

-- 对外错误码 -> HTTP 状态码映射。
-- 必须与 WAF 侧 internal/responder/status.go 的映射保持一致。
local CODE_TO_STATUS = {
    WAF_BLOCKED      = 403,
    WAF_UNAUTHORIZED = 401,
    WAF_RATE_LIMITED = 429,
    WAF_BAD_REQUEST  = 400,
    WAF_UNAVAILABLE  = 503,
}

-- 需要从 WAF 响应透传给客户端的响应头。
local PASSTHROUGH_HEADERS = {
    "X-WAF-Request-Id",
    "X-WAF-Verdict",
    "X-WAF-Code",
    "X-WAF-Rule-Id",
    "X-WAF-Version",
    "X-WAF-Site",
    "Retry-After",
    "WWW-Authenticate",
}

-- 鉴权子请求端点（对应 nginx.conf 中的 location = /__waf_auth）。
local AUTH_SUBREQUEST_URI = "/__waf_auth"

-- 兜底 JSON 错误体（含变量插值）：WAF 未返回响应体时使用，保证响应格式始终是 JSON。
local FALLBACK_BODY_TEMPLATE =
    '{"code":"%s","message":"安全检测服务暂时不可用","request_id":""}'

-- -----------------------------------------------------------------------------
-- 内部函数
-- -----------------------------------------------------------------------------

-- injectOriginalRequestHeaders 把「原始请求」信息写入当前请求头。
--
-- 写完之后子请求会自动继承这些请求头（nginx 子请求共享父请求的 headers_in），
-- 内部 location 再按 $http_x_forwarded_* 原样透传给 WAF。
local function injectOriginalRequestHeaders()
    -- X-Forwarded-For 取「已有链 + 本机地址」，避免把上游 CDN 的链路抹掉；
    -- 该变量必须在覆盖请求头之前读取。
    local forwarded_for = ngx.var.proxy_add_x_forwarded_for
    if not forwarded_for or forwarded_for == "" then
        forwarded_for = ngx.var.remote_addr
    end

    ngx.req.set_header("X-Forwarded-For",    forwarded_for)
    ngx.req.set_header("X-Real-IP",          ngx.var.remote_addr)
    ngx.req.set_header("X-Forwarded-Proto",  ngx.var.scheme)
    ngx.req.set_header("X-Forwarded-Host",   ngx.var.host)
    ngx.req.set_header("X-Forwarded-Uri",    ngx.var.request_uri)
    ngx.req.set_header("X-Forwarded-Method", ngx.req.get_method())
    -- X-Original-URI 是 WAF 侧 ingress.headers.uri 的次选候选，一并注入以便兼容。
    ngx.req.set_header("X-Original-URI",     ngx.var.request_uri)
end

-- readRequestBody 读取当前请求的请求体，并按上限截断。
--
-- 返回值：请求体字符串；无请求体时返回 nil。
-- 说明：OpenResty 会把超过 client_body_buffer_size 的请求体落盘，
-- 此时 get_body_data() 返回 nil，需要从 get_body_file() 读取。
-- 为避免整体读入超大文件，这里先检查文件大小，只读取前 MAX_FORWARD_BODY_BYTES 字节。
local function readRequestBody()
    ngx.req.read_body()

    local body = ngx.req.get_body_data()

    if not body then
        local body_file = ngx.req.get_body_file()
        if not body_file then
            return nil
        end

        local file = io.open(body_file, "rb")
        if not file then
            return nil
        end
        -- 只读取上限字节，避免大体积读取（与 WAF 侧「不做大体积读取」的约束呼应）。
        body = file:read(MAX_FORWARD_BODY_BYTES)
        file:close()
    end

    if not body or #body == 0 then
        return nil
    end
    if #body > MAX_FORWARD_BODY_BYTES then
        body = string.sub(body, 1, MAX_FORWARD_BODY_BYTES)
    end
    return body
end

-- emitDeny 依据 WAF 的结论写出对外响应。
--
-- 参数：
--   res    是 ngx.location.capture 的返回结果（可能为 nil）；
--   status 是对外状态码。
local function emitDeny(res, status)
    if res then
        for _, name in ipairs(PASSTHROUGH_HEADERS) do
            local value = res.headers[name]
            if value then
                ngx.header[name] = value
            end
        end
    end

    -- 未拿到 WAF 响应体时使用兜底 JSON，保证「响应体永远是 JSON」这一对外契约。
    local body
    if res and res.body and #res.body > 0 then
        body = res.body
    else
        body = string.format(FALLBACK_BODY_TEMPLATE, "WAF_UNAVAILABLE")
        ngx.header["X-WAF-Code"] = "WAF_UNAVAILABLE"
        ngx.header["X-WAF-Verdict"] = "unavailable"
    end

    -- Content-Type 必须显式设置：某些场景下 WAF 的响应头可能未被透传。
    if not ngx.header["Content-Type"] then
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
    end
    -- 拦截响应禁止被缓存。
    ngx.header["Cache-Control"] = "no-store"

    ngx.status = status
    ngx.print(body)
    -- 使用 ngx.exit(ngx.HTTP_OK) 结束请求：此时状态码已在 ngx.status 中设定，
    -- 若传入具体错误码反而会触发 Nginx 的 error_page 机制，覆盖我们已写好的响应体。
    ngx.exit(ngx.HTTP_OK)
end

-- -----------------------------------------------------------------------------
-- 对外接口
-- -----------------------------------------------------------------------------

-- check 执行一次鉴权；放行时直接返回，拦截时直接结束请求。
--
-- 在 nginx.conf 中的调用方式：
--   access_by_lua_block { require("waf_auth").check() }
function _M.check()
    -- 先注入原始请求信息：必须早于 capture，子请求才能继承到这些头。
    injectOriginalRequestHeaders()

    local body = readRequestBody()

    -- 构造子请求选项。
    --
    -- 方法选择策略：
    --   - 无请求体时沿用原始方法（GET / HEAD / DELETE 等保持语义）；
    --   - 有请求体且原始方法是 GET / HEAD 时改用 POST：
    --     HTTP 语义上 GET/HEAD 不应携带请求体，部分中间层会直接丢弃请求体，
    --     改用 POST 可以稳定地把请求体送到 WAF；原始方法已通过
    --     X-Forwarded-Method 告知 WAF，判定语义不受影响。
    local method = ngx.req.get_method()
    if body and (method == "GET" or method == "HEAD") then
        method = ngx.HTTP_POST
    end

    local capture_opts = {
        method = method,
        -- 鉴权子请求不跟随重定向，避免被中间层劫持；
        -- 子请求指向的内部 location 已通过 internal 指令限制外部访问。
        ctx = ngx.ctx,
    }
    if body then
        capture_opts.body = body
    end

    local res = ngx.location.capture(AUTH_SUBREQUEST_URI, capture_opts)

    -- 子请求失败（连接失败 / 超时 / 内部错误）。
    if not res or res.status == 0 then
        if FAIL_OPEN then
            ngx.log(ngx.ERR, "waf_auth: 鉴权子请求失败，按配置放行请求")
            return
        end
        ngx.log(ngx.ERR, "waf_auth: 鉴权子请求失败，按失败关闭策略拦截请求")
        emitDeny(nil, 503)
        return
    end

    -- 放行：把 WAF 回传的请求标识与判定结论透传给业务，便于日志串联。
    if res.status >= 200 and res.status < 300 then
        local request_id = res.headers["X-WAF-Request-Id"]
        if request_id then
            ngx.header["X-WAF-Request-Id"] = request_id
        end
        local verdict = res.headers["X-WAF-Verdict"]
        if verdict then
            ngx.header["X-WAF-Verdict"] = verdict
        end
        return
    end

    -- 拦截：优先按 X-WAF-Code 还原对外状态码（Nginx 通道下 WAF 统一回 403）。
    local code = res.headers["X-WAF-Code"]
    local status = CODE_TO_STATUS[code] or res.status
    if status < 400 then
        -- 理论上不会发生；一旦发生说明 WAF 与脚本的契约被破坏，按 403 兜底而不是放行。
        status = 403
    end

    emitDeny(res, status)
end

return _M