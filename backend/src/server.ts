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

app.post("/api/pin", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const jwt = process.env.PINATA_JWT;
    if (!jwt) return res.status(500).json({ error: "PINATA_JWT not set" });

    const fileHash = sha256Hex(req.file.buffer);

    // Pinata V3 upload endpoint (important: uploads.pinata.cloud)
    const url = "https://uploads.pinata.cloud/v3/files";

    const form = new FormData();
    form.append("file", req.file.buffer, { filename: req.file.originalname });

    // Recommended for V3: specify network as "public"
    form.append("network", "public");

    const pinataRes = await axios.post(url, form, {
      headers: {
        Authorization: `Bearer ${jwt}`,
        ...form.getHeaders(),
      },
      maxBodyLength: Infinity,
    });

    // Be tolerant to response shape differences
    const cid =
      pinataRes.data?.data?.cid || pinataRes.data?.cid || pinataRes.data?.IpfsHash;

    if (!cid) {
      console.log("Unexpected Pinata response:", pinataRes.data);
      return res.status(500).json({
        error: "Pinata response missing cid",
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

const port = Number(process.env.PORT || 5050);
app.listen(port, () => {
  console.log(`Backend running on http://localhost:${port}`);
});
