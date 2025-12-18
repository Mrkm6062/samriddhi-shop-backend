import { Storage } from '@google-cloud/storage';
import dotenv from 'dotenv';

dotenv.config();

if (!process.env.GCS_KEYFILE_PATH) {
  throw new Error('GCS_KEYFILE_PATH is missing');
}

if (!process.env.GCS_BUCKET) {
  throw new Error('GCS_BUCKET is missing');
}

const storage = new Storage({
  keyFilename: process.env.GCS_KEYFILE_PATH
});

export { storage };
