// Storage configuration for different environments
const multer = require('multer');
const path = require('path');

// For DigitalOcean App Platform deployment, you should use DigitalOcean Spaces
// This is a basic configuration that works locally and can be extended for cloud storage

const createStorageConfig = () => {
    // Check if we're in production and have cloud storage configured
    const useCloudStorage = process.env.NODE_ENV === 'production' && 
                           process.env.DO_SPACES_ENDPOINT && 
                           process.env.DO_SPACES_BUCKET;

    if (useCloudStorage) {
        // TODO: Implement DigitalOcean Spaces integration
        // You would use a library like @aws-sdk/client-s3 (since Spaces is S3-compatible)
        console.log('Cloud storage configuration detected but not implemented yet');
        console.log('Falling back to local storage (files will be lost on redeploy)');
    }

    // Default local storage configuration
    return multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, 'uploads/')
        },
        filename: function (req, file, cb) {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
        }
    });
};

const createUploadMiddleware = () => {
    const storage = createStorageConfig();
    
    return multer({
        storage: storage,
        limits: {
            fileSize: 5 * 1024 * 1024 // 5MB limit
        },
        fileFilter: function (req, file, cb) {
            // Check if file is an image
            if (file.mimetype.startsWith('image/')) {
                cb(null, true);
            } else {
                cb(new Error('Only image files are allowed!'), false);
            }
        }
    });
};

module.exports = {
    createStorageConfig,
    createUploadMiddleware
};
