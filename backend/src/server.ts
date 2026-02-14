// backend/src/server.ts
import express from "express";
import cors from "cors";
import multer from "multer";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";
import FormData from "form-data";

dotenv.config();

// Safe JWT fingerprint (helps confirm backend loaded the right .env)
const loadedJwt = process.env.PINATA_JWT || "";
console.log(
  "PINATA_JWT loaded:",
  loadedJwt ? `${loadedJwt.slice(0, 12)}...${loadedJwt.slice(-6)}` : "(missing)"
);

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ storage: multer.memoryStorage() });

function sha256Hex(buffer: Buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

/**
 * Upload (Pin) a file to Pinata/IPFS
 * Uses LEGACY pinFileToIPFS endpoint because your key scopes are enabled there.
 *
 * Request: multipart/form-data with field name "file"
 * Response: { cid, fileHash }
 */
app.post("/api/pin", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const jwt = process.env.PINATA_JWT;
    if (!jwt) return res.status(500).json({ error: "PINATA_JWT not set" });

    const fileHash = sha256Hex(req.file.buffer);

    // Legacy endpoint (works with pinFileToIPFS scope)
    const url = "https://api.pinata.cloud/pinning/pinFileToIPFS";

    const form = new FormData();
    form.append("file", req.file.buffer, { filename: req.file.originalname });

    // Optional: attach metadata (safe)
    // form.append("pinataMetadata", JSON.stringify({ name: req.file.originalname }));

    const pinataRes = await axios.post(url, form, {
      headers: {
        Authorization: `Bearer ${jwt}`,
        ...form.getHeaders(),
      },
      maxBodyLength: Infinity,
    });

    // Legacy response: { IpfsHash: "Qm...", ... }
    const cid = pinataRes.data?.IpfsHash;

    if (!cid) {
      console.log("Unexpected Pinata response:", pinataRes.data);
      return res.status(500).json({
        error: "Pinata response missing IpfsHash",
        response: pinataRes.data,
      });
    }

    return res.json({ cid, fileHash });
  } catch (err: any) {
    const status = err?.response?.status;
    const details = err?.response?.data || err?.message || String(err);

    console.error("Pinata upload failed. Status:", status);
    console.error("Details:", details);

    return res.status(500).json({
      error: "Pinata upload failed",
      status,
      details,
    });
  }
});

/**
 * Fetch raw bytes for a CID from a PUBLIC gateway.
 * IMPORTANT: No JWT here. Gateways are public reads.
 * This prevents hashing an HTML/JSON error page by accident.
 */
app.get("/api/fetch/:cid", async (req, res) => {
  try {
    const { cid } = req.params;

    // Public Pinata gateway
    const url = `https://gateway.pinata.cloud/ipfs/${cid}`;

    const response = await axios.get(url, {
      responseType: "arraybuffer",
      maxBodyLength: Infinity,
      validateStatus: () => true, // allow non-200 so we can return debug info
    });

    if (response.status !== 200) {
      const preview = Buffer.from(response.data)
        .toString("utf8")
        .slice(0, 200);

      return res.status(502).json({
        error: "Gateway fetch failed",
        upstreamStatus: response.status,
        upstreamPreview: preview,
        cid,
      });
    }

    res.setHeader("Content-Type", "application/octet-stream");
    res.send(Buffer.from(response.data));
  } catch (err: any) {
    console.error("Fetch crashed:", err?.message);

    return res.status(500).json({
      error: "Fetch crashed",
      message: err?.message || String(err),
    });
  }
});

const port = Number(process.env.PORT || 5050);
app.listen(port, () => {
  console.log(`Backend running on http://localhost:${port}`);
});
