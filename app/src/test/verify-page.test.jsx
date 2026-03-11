import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BrowserRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App";

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

describe("public verify flow", () => {
  it("verifies a certificate from pasted QR URL input and renders public proof details", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
      const urlString = String(url);

      if (urlString.includes("/api/verify/cert-123")) {
        return jsonResponse({
          status: "VALID",
          certId: "cert-123",
          issuer: "0xabc123",
          metadataCid: "bafy-meta",
          storageMode: "encrypted-blob",
          encryptionAlg: "aes-256-gcm",
          version: 1,
          replacesCertId: "",
          integrityMatch: true,
          revoked: false,
        });
      }

      if (urlString.includes("/api/certificates/cert-123/history")) {
        return jsonResponse({
          rootCertId: "cert-123",
          chainLength: 1,
          chain: [
            {
              certId: "cert-123",
              version: 1,
              revoked: false,
              issuedAt: 1710000000,
            },
          ],
        });
      }

      throw new Error(`Unexpected fetch URL: ${urlString}`);
    });

    window.history.pushState({}, "", "/verify");

    render(
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <App />
      </BrowserRouter>
    );

    await userEvent.type(
      screen.getByLabelText(/scan\/paste qr url or certificate id/i),
      "https://trustmycert.example/verify?certId=cert-123"
    );
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));

    expect(await screen.findByRole("heading", { name: "VALID" })).toBeInTheDocument();
    expect(screen.getByText(/public verification hides recipient details/i)).toBeInTheDocument();
    expect(screen.getByText(/encrypted-blob/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });
});
