import { Storage } from '@google-cloud/storage';
import dotenv from 'dotenv';

dotenv.config();

// Initialize Google Cloud Storage client
// It will use GCS_KEYFILE_PATH from .env if provided, otherwise it falls back to Application Default Credentials
const storage = new Storage({
  projectId: process.env.GCS_PROJECT_ID,
  keyFilename: process.env.GCS_KEYFILE_PATH,
});

export { storage };