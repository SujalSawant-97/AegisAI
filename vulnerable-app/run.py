import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("  Starting Vulnerable Test Application on http://localhost:8082")
    print("  - Target URL: http://localhost:8082")
    print("  - OpenAPI Spec: http://localhost:8082/openapi.json")
    print("  - Interactive Docs: http://localhost:8082/docs")
    print("=" * 70)
    uvicorn.run("app:app", host="0.0.0.0", port=8082, reload=False)
