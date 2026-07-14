import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import { ObjectId } from "mongodb";
import { connectToDatabase } from "./db";
import { hashPassword, verifyPassword, signToken, verifyToken } from "./auth";

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
        name: user.name || "",
        email: user.email,
        role: user.role,
        imageUrl: user.imageUrl || "",
        createdAt: user.createdAt,
      },
    });
  } catch (err: any) {
    console.error("Login Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 4. Get current user profile (GET /api/auth/me)
app.get("/api/auth/me", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    const { db } = await connectToDatabase();
    const user = await db.collection("users").findOne({ email: payload.email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({
      id: user._id.toString(),
      name: user.name || "",
      email: user.email,
      role: user.role,
      imageUrl: user.imageUrl || "",
      createdAt: user.createdAt,
    });
  } catch (err: any) {
    console.error("Get Me Error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 5. Update current user profile (PATCH /api/auth/me)
app.patch("/api/auth/me", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    const { name, imageUrl } = req.body;
    const updates: Record<string, string> = {};
    if (typeof name === "string") updates.name = name.trim();
    if (typeof imageUrl === "string") updates.imageUrl = imageUrl.trim();
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    let userId: ObjectId;
    try {
      userId = new ObjectId(payload.userId);
    } catch {
      return res.status(400).json({ message: "Invalid user ID in token" });
    }

    const { db } = await connectToDatabase();
    const result = await db.collection("users").findOneAndUpdate(
      { email: payload.email },
      { $set: updates },
      { returnDocument: "after" }
    );

    if (!result) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      id: result._id.toString(),
      name: result.name || "",
      email: result.email,
      role: result.role,
      imageUrl: result.imageUrl || "",
      createdAt: result.createdAt,
    });
  } catch (err: any) {
    console.error("[PATCH /api/auth/me] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// 6. Get All Plants Route
app.get("/api/plants", async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const plants = await db.collection("plants").find({}).sort({ _id: -1 }).toArray();
    
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

// 7. Create a New Plant (Admin only)
app.post("/api/plants", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.slice(7);
    const payload = verifyToken(token);
    if (!payload || payload.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin access required" });
    }
    const {
      title, scientificName, category, short, description,
      price, image, difficulty, watering, sunlight,
      temperature, detailedCare, commonProblems,
    } = req.body;
    if (!title || !price || !image) {
      return res.status(400).json({ message: "title, price, and image are required" });
    }
    const { db } = await connectToDatabase();
    const newPlant = {
      title: String(title).trim(),
      scientificName: String(scientificName || "").trim(),
      category: String(category || "Foliage").trim(),
      short: String(short || "").trim(),
      description: String(description || "").trim(),
      price: Number(price),
      image: String(image).trim(),
      difficulty: ["Easy", "Medium", "Hard"].includes(difficulty) ? difficulty : "Easy",
      watering: String(watering || "").trim(),
      sunlight: String(sunlight || "").trim(),
      temperature: String(temperature || "").trim(),
      detailedCare: Array.isArray(detailedCare) ? detailedCare : [],
      commonProblems: Array.isArray(commonProblems) ? commonProblems : [],
      createdAt: new Date(),
    };
    const result = await db.collection("plants").insertOne(newPlant);
    return res.status(201).json({ message: "Plant created successfully", id: result.insertedId.toString() });
  } catch (err: any) {
    console.error("[POST /api/plants] Error:", err?.message || err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Start Express server
app.listen(PORT, () => {
  console.log(`[server] LushLeaves server is running on http://localhost:${PORT}`);
});
