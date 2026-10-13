#!/bin/bash

# AEGENTRA Vulnerable Test Application Setup Script
# This script sets up the vulnerable application for testing

echo "🚀 Setting up AEGENTRA Vulnerable Test Application..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p database uploads

# Build and run the container
echo "🐳 Building Docker image..."
docker-compose build

echo "🚀 Starting the application..."
docker-compose up -d

# Wait for the application to start
echo "⏳ Waiting for application to start..."
sleep 5

# Check if the application is running
if curl -s http://localhost:8085 > /dev/null; then
    echo "✅ Application is running successfully!"
    echo ""
    echo "🌐 Access the application at: http://localhost:8085"
    echo ""
    echo "📋 Test Accounts:"
    echo "   admin / password123"
    echo "   user1 / 123456"
    echo "   test  / test"
    echo "   guest / guest"
    echo ""
    echo "🧪 Quick Test Commands:"
    echo "   SQL Injection: Try login with username: ' OR '1'='1"
    echo "   XSS: Add comment with: <script>alert(1)</script>"
    echo "   Admin Access: Go to http://localhost:8085/admin after login"
    echo ""
    echo "🔧 To stop the application: docker-compose down"
    echo "📖 For more info: cat README.md"
else
    echo "❌ Application failed to start. Check the logs:"
    echo "   docker-compose logs vulnerable-app"
fi