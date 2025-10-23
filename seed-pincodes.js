import mongoose from 'mongoose';
import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

// --- Configuration ---
const API_KEY = process.env.DATA_GOV_IN_API_KEY; // Make sure to set this in your .env file
const API_URL = 'https://api.data.gov.in/resource/6176ee09-3d56-4a3b-8115-21841576b2f6';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/samriddhishop';
const RECORDS_PER_FETCH = 1000; // The API limit per request

// --- Pincode Schema ---
// This should match the schema in your main server.js file
const pincodeSchema = new mongoose.Schema({
  officeName: { type: String, required: true },
  pincode: { type: Number, required: true, index: true },
  officeType: String,
  deliveryStatus: String,
  districtName: { type: String, required: true, index: true },
  stateName: { type: String, required: true, index: true },
  deliverable: { type: Boolean, default: false, index: true } // Default to not deliverable
});

// Create a unique compound index to prevent duplicate entries
pincodeSchema.index({ officeName: 1 }, { unique: true });

const Pincode = mongoose.model('Pincode', pincodeSchema);


const fetchAndSeedPincodes = async () => {
  if (!API_KEY) {
    console.error('Error: DATA_GOV_IN_API_KEY is not defined in your .env file.');
    return;
  }

  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected for seeding...');

    let offset = 0;
    let totalRecords = 0;
    let hasMore = true;

    while (hasMore) {
      const url = `${API_URL}?api-key=${API_KEY}&format=json&offset=${offset}&limit=${RECORDS_PER_FETCH}`;
      console.log(`Fetching records from offset ${offset}...`);

      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`API request failed with status ${response.status}`);
      }

      const data = await response.json();
      const records = data.records;

      if (records && records.length > 0) {
        const bulkOps = records.map(record => ({
          updateOne: {
            filter: { officeName: record.officename },
            update: {
              $set: {
                pincode: parseInt(record.pincode, 10),
                officeType: record.officetype,
                deliveryStatus: record.deliverystatus,
                districtName: record.districtname,
                stateName: record.statename,
              },
              // On initial insert, set the deliverable status
              $setOnInsert: { deliverable: false }
            },
            upsert: true // Insert if it doesn't exist, update if it does
          }
        }));

        await Pincode.bulkWrite(bulkOps);
        
        totalRecords += records.length;
        console.log(`Inserted/updated ${records.length} records. Total so far: ${totalRecords}`);
        offset += records.length;
      } else {
        hasMore = false;
        console.log('No more records to fetch.');
      }
    }

    console.log(`Seeding complete! A total of ${totalRecords} pincode records have been processed.`);
  } catch (error) {
    console.error('An error occurred during the seeding process:', error);
  } finally {
    await mongoose.disconnect();
    console.log('MongoDB disconnected.');
  }
};

fetchAndSeedPincodes();