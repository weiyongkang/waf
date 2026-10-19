package apisec

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const testSpec = `openapi: 3.0.3
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: integer
          minimum: 1
    get:
      parameters:
        - name: q
          in: query
          required: true
          schema:
            type: string
            minLength: 2
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/User'
  /users/me:
    get:
      parameters:
        - name: X-Token
          in: header
          required: true
          schema:
            type: string
            pattern: '^[a-z]+$'
components:
  schemas:
    User:
      type: object
      additionalProperties: false
      required: [name, email]
      properties:
        name:
          type: string
          minLength: 3
        email:
          type: string
          pattern: '^[^@]+@[^@]+$'
`

func mustSpec(t *testing.T) *Spec {
	t.Helper()
	spec, err := Parse([]byte(testSpec))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return spec
}

func TestMatchPrefersLiteralRoute(t *testing.T) {
	spec := mustSpec(t)
	route, _ := spec.Match("GET", "/users/me")
	if route == nil || route.Path != "/users/me" {
		t.Fatalf("literal route not selected: %#v", route)
	}
	route, params := spec.Match("GET", "/users/42")
	if route == nil || route.Path != "/users/{id}" || params["id"] != "42" {
		t.Fatalf("parameter route mismatch: route=%#v params=%v", route, params)
	}
}

func TestValidateParameters(t *testing.T) {
	spec := mustSpec(t)
	matched, violations := spec.Validate("GET", "/users/42", url.Values{"q": []string{"ab"}},
		http.Header{}, nil, true, false, 8)
	if !matched || len(violations) != 0 {
		t.Fatalf("valid request rejected: matched=%v violations=%v", matched, violations)
	}

	_, violations = spec.Validate("GET", "/users/42", url.Values{}, http.Header{}, nil, true, false, 8)
	if len(violations) != 1 || violations[0].Rule != "parameter_required" {
		t.Fatalf("missing query not reported: %v", violations)
	}

	_, violations = spec.Validate("GET", "/users/42", url.Values{"q": []string{"a"}},
		http.Header{}, nil, true, false, 8)
	if len(violations) != 1 || violations[0].Rule != "schema_min_length" {
		t.Fatalf("minLength not enforced: %v", violations)
	}

	_, violations = spec.Validate("GET", "/users/abc", url.Values{"q": []string{"ab"}},
		http.Header{}, nil, true, false, 8)
	if len(violations) != 1 || violations[0].Rule != "parameter_type" {
		t.Fatalf("path integer not enforced: %v", violations)
	}

	_, violations = spec.Validate("GET", "/users/me", url.Values{},
		http.Header{"X-Token": []string{"ABC"}}, nil, true, false, 8)
	if len(violations) != 1 || violations[0].Rule != "schema_pattern" {
		t.Fatalf("header pattern not enforced: %v", violations)
	}
}

func TestValidateJSONBody(t *testing.T) {
	spec := mustSpec(t)
	header := http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}
	valid := []byte(`{"name":"alice","email":"a@b.com"}`)
	matched, violations := spec.Validate("POST", "/users/42", url.Values{}, header, valid, true, true, 8)
	if !matched || len(violations) != 0 {
		t.Fatalf("valid body rejected: matched=%v violations=%v", matched, violations)
	}

	missing := []byte(`{"name":"alice"}`)
	_, violations = spec.Validate("POST", "/users/42", url.Values{}, header, missing, true, true, 8)
	if len(violations) != 1 || violations[0].Rule != "schema_required" {
		t.Fatalf("required field not enforced: %v", violations)
	}

	extra := []byte(`{"name":"alice","email":"a@b.com","admin":true}`)
	_, violations = spec.Validate("POST", "/users/42", url.Values{}, header, extra, true, true, 8)
	if len(violations) != 1 || violations[0].Rule != "schema_additional_property" {
		t.Fatalf("additionalProperties not enforced: %v", violations)
	}

	_, violations = spec.Validate("POST", "/users/42", url.Values{}, header, []byte(`{`), true, true, 8)
	if len(violations) != 1 || violations[0].Rule != "body_json" {
		t.Fatalf("invalid JSON not enforced: %v", violations)
	}

	wrongType := http.Header{"Content-Type": []string{"text/plain"}}
	_, violations = spec.Validate("POST", "/users/42", url.Values{}, wrongType, valid, true, true, 8)
	if len(violations) != 1 || violations[0].Rule != "body_content_type" {
		t.Fatalf("content type not enforced: %v", violations)
	}
}

func TestValidateUnknownRoute(t *testing.T) {
	spec := mustSpec(t)
	matched, violations := spec.Validate("GET", "/missing", url.Values{}, http.Header{}, nil, true, false, 8)
	if matched || len(violations) != 0 {
		t.Fatalf("unknown route should not be claimed by spec: matched=%v violations=%v", matched, violations)
	}
}

func TestParseRejectsUnsupportedOpenAPI(t *testing.T) {
	_, err := Parse([]byte("openapi: 2.0\npaths: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "OpenAPI 3.x") {
		t.Fatalf("unexpected error: %v", err)
	}
}
