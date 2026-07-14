import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import { connectToDatabase } from "./db";
import { hashPassword, verifyPassword, signToken } from "./auth";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS and JSON parsing
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Multer memory storage configuration for file uploads
const upload = multer({ storage: multer.memoryStorage() });

app.get("/", (req, res) => {
  res.json({ message: "LushLeaves server is running" });
});

// 1. Image Upload Route (proxies multipart image upload to ImgBB)
app.post("/api/upload-image", upload.single("image"), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ success: false, message: "No image file provided." });
    }

    const apiKey = process.env.IMGBB_API_KEY || "d0c007137f61c3606f7b18991207131b";
    const base64Image = file.buffer.toString("base64");

    const imgbbForm = new FormData();
    imgbbForm.append("key", apiKey);
    imgbbForm.append("image", base64Image);

    const imgbbRes = await fetch("https://api.imgbb.com/1/upload", {
      method: "POST",
      body: imgbbForm,
    });

    const imgbbData = await imgbbRes.json() as any;

    if (!imgbbRes.ok || !imgbbData.success) {
      return res.status(502).json({
        success: false,
        message: imgbbData?.error?.message || "ImgBB upload failed.",
      });
    }

    return res.status(200).json({
      success: true,
      url: imgbbData.data.url,
    });
  } catch (err) {
    console.error("[upload-image] Server error:", err);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// 2. Auth Register Route
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, role, imageUrl, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const { db } = await connectToDatabase();

    // Check if user already exists
    const existingUser = await db.collection("users").findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: "User with this email already exists." });
    }

    const userRole = role === "admin" ? "admin" : "user";
    const passwordHash = hashPassword(password);
    const now = new Date();

    const newUser = {
      name: name || "",
      email: email.toLowerCase(),
      passwordHash,
      role: userRole,
      imageUrl: imageUrl || "",
      createdAt: now,
    };

    const result = await db.collection("users").insertOne(newUser);
    const userId = result.insertedId.toString();

    // Generate JWT
    const token = signToken({
      userId,
      email: newUser.email,
      role: userRole,
    });

    return res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: userId,
        name: newUser.name,
        email: newUser.email,
        role: userRole,
        imageUrl: newUser.imageUrl,
      },
    });
  } catch (err: any) {
    console.error("Register Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 3. Auth Login Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const { db } = await connectToDatabase();

    const user = await db.collection("users").findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = verifyPassword(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const token = signToken({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });

    return res.status(200).json({
      message: "Logged in successfully",
      token,
      user: {
        id: user._id.toString(),
        email: user.email,
        role: user.role,
      },
    });
  } catch (err: any) {
    console.error("Login Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 4. Get All Plants Route
app.get("/api/plants", async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const plants = await db.collection("plants").find({}).toArray();
    
    // Map _id to string id for the frontend
    const mappedPlants = plants.map((plant: any) => ({
      id: plant._id.toString(),
      title: plant.title,
      scientificName: plant.scientificName || "",
      category: plant.category || "Foliage",
      short: plant.short || "",
      description: plant.description || "",
      price: plant.price || 0,
      image: plant.image || "",
      difficulty: plant.difficulty || "Easy",
      watering: plant.watering || "",
      sunlight: plant.sunlight || "",
      temperature: plant.temperature || "",
      detailedCare: plant.detailedCare || [],
      commonProblems: plant.commonProblems || [],
    }));

    return res.status(200).json(mappedPlants);
  } catch (err: any) {
    console.error("Fetch Plants Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Start Express server
app.listen(PORT, () => {
  console.log(`[server] LushLeaves server is running on http://localhost:${PORT}`);
});
