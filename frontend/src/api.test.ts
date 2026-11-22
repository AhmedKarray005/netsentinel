import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, errorMessage, queryString } from "./api";

afterEach(() => vi.unstubAllGlobals());

function mockFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue(
    new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("queryString", () => {
  it("drops empty filters and encodes values", () => {
    expect(queryString({ protocol: "", ip: "2a01::1", port: 443, since: null, sort: undefined })).toBe(
      "?ip=2a01%3A%3A1&port=443",
    );
    expect(queryString({})).toBe("");
  });
});

describe("errorMessage", () => {
  it("reads FastAPI text and validation errors", () => {
    expect(errorMessage({ detail: "Analysis 9 not found" }, "x")).toBe("Analysis 9 not found");
    expect(errorMessage({ detail: [{ msg: "bad port" }, { msg: "bad ip" }] }, "x")).toBe("bad port; bad ip");
    expect(errorMessage("not json", "fallback")).toBe("fallback");
  });
});

describe("api client", () => {
  it("calls the flows endpoint with only the chosen filters", async () => {
    const fetchMock = mockFetch(200, { items: [], total: 0, limit: 50, offset: 0 });
    await api.listFlows(3, { protocol: "TCP", tcp_state: "", ip: "", port: "", limit: 50, offset: 0 });
    expect(fetchMock).toHaveBeenCalledWith("/api/analyses/3/flows?protocol=TCP&limit=50&offset=0", undefined);
  });

  it("turns an HTTP error into an ApiError with the server's message", async () => {
    mockFetch(415, { detail: "Only ['.cap', '.pcap', '.pcapng'] files are accepted" });
    const error = await api.uploadCapture(new File(["x"], "evil.exe")).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(415);
    expect((error as ApiError).message).toContain("files are accepted");
  });

  it("explains when the API server is not running", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const error = (await api.health().catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(0);
    expect(error.message).toContain("netsentinel serve");
  });

  it("accepts 204 No Content on delete", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(api.deleteAnalysis(1)).resolves.toBeUndefined();
  });
});
