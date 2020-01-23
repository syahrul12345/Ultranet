# Build the frontend code.
if [ $1 -z ]
then
  echo 'Building the frontend code...'
  ( cd frontend && ng build --prod )
fi

# Create the output directory for the binaries. Assume we build on Linux.
echo 'Cleaning previous builds...'
BINARY_DIR=../../bin/ultranet_binaries
rm -rf $BINARY_DIR
echo "Creating output directory for binaries at $BINARY_DIR"
mkdir -p $BINARY_DIR

echo 'Building for 64-bit Linux...'
( cd backend && packr && GOOS=linux GOARCH=amd64 go build && cd .. && mv backend/backend $BINARY_DIR/ultranet_linux_amd64)

echo 'Building for 32-bit Linux...'
( cd backend && packr && GOOS=linux GOARCH=386 go build && cd .. && mv backend/backend $BINARY_DIR/ultranet_linux_386)

echo 'Building for 64-bit Mac...'
( cd backend && packr && GOOS=darwin GOARCH=amd64 go build && cd .. && mv backend/backend $BINARY_DIR/ultranet_darwin_amd64)

echo 'Building for 32-bit Mac...'
( cd backend && packr && GOOS=darwin GOARCH=386 go build && cd .. && mv backend/backend $BINARY_DIR/ultranet_darwin_386)

echo 'Building for 64-bit Windows...'
( cd backend && packr && GOOS=windows GOARCH=amd64 go build && cd .. && mv backend/backend.exe $BINARY_DIR/ultranet_windows_amd64.exe)

echo 'Building for 32-bit Windows...'
( cd backend && packr && GOOS=windows GOARCH=386 go build && cd .. && mv backend/backend.exe $BINARY_DIR/ultranet_windows_386.exe)

echo 'Creating local copy of binaries...'
sudo rm -rf /root/ultranet_binaries
sudo cp -R $BINARY_DIR /root/
