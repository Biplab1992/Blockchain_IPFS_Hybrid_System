import express from "express";
import cors from "cors";
import multer from "multer";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";
import FormData from "form-data";

dotenv.config();

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
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const jwt = process.env.PINATA_JWT;
    if (!jwt) {
      return res.status(500).json({ error: "PINATA_JWT not set" });
    }

    const fileHash = sha256Hex(req.file.buffer);

    const form = new FormData();
    form.append("file", req.file.buffer, {
      filename: req.file.originalname,
    });

    const pinataRes = await axios.post(
      "https://api.pinata.cloud/pinning/pinFileToIPFS",
      form,
      {
        headers: {
          Authorization: `Bearer ${jwt}`,
          ...form.getHeaders(),
        },
        maxBodyLength: Infinity,
      }
    );

    const cid = pinataRes.data.IpfsHash;

    return res.json({ cid, fileHash });
  } catch (err: any) {
    console.error(err?.response?.data || err);
    return res.status(500).json({ error: "Pinata upload failed" });
  }
});

const port = Number(process.env.PORT || 5050);
app.listen(port, () => {
  console.log(`Backend running on http://localhost:${port}`);
});
