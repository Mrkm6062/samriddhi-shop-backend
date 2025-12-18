import { Storage } from '@google-cloud/storage';
import dotenv from 'dotenv';

dotenv.config();

// Initialize Google Cloud Storage client
const storageConfig = {
  projectId: process.env.GCS_PROJECT_ID,
};

// Prioritize key file path if exists (Development)
if (process.env.GCS_KEYFILE_PATH) {
  storageConfig.keyFilename = process.env.GCS_KEYFILE_PATH;
} 
// Fallback to JSON credentials from env var (Production/Render/Heroku)
else if (process.env.GCS_CREDENTIALS) {
  try {
    storageConfig.credentials = JSON.parse(process.env.GCS_CREDENTIALS);
  } catch (err) {
    console.error('Error parsing GCS_CREDENTIALS:', err);
  }
}

const storage = new Storage(storageConfig);

export { storage };