import { MongoClient, Db } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const uri = process.env.MONGODB_URI || "mongodb+srv://LushLeaves:MPsDSTQi6JBjJEQz@cluster0.1oucwva.mongodb.net/?appName=Cluster0";
const options = {};

let client: MongoClient | null = null;
let clientPromise: Promise<MongoClient> | null = null;

export async function connectToDatabase(): Promise<{ client: MongoClient; db: Db }> {
  // Safe logging of current database host connection (hiding credentials)
  const host = uri.split("@")[1] || "localhost";
  console.log(`[db] Connecting to MongoDB host: ${host}`);

  if (!client || !clientPromise) {
    client = new MongoClient(uri, options);
    clientPromise = client.connect();
  }

  try {
    const connectedClient = await clientPromise;
    const db = connectedClient.db("LushLeaves");
    return { client: connectedClient, db };
  } catch (error) {
    // Reset connection promise on failure so next request tries a clean reconnect
    client = null;
    clientPromise = null;
    throw error;
  }
}

