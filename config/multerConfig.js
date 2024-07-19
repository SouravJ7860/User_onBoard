// config/multerConfig.js

const multer = require('multer');
const path = require('path');
// const fs = require('fs')

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '../uploads'));
      },
      filename: (req, file, cb) => {
        console.log('file: ', file);
        cb(null, 'image_' + Date.now() + file.originalname);
      }
    });

const upload = multer({ storage });

module.exports = upload;
