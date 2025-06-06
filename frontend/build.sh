#!/bin/bash

# Build frontend
echo "Building frontend..."
cd frontend
npm run build

# Move frontend build to backend static folder
echo "Moving frontend build to backend..."
rm -rf ../static
mv dist ../static

# Return to root directory
cd ..

echo "Build complete! The application is ready for deployment."
