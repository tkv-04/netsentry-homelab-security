# React dashboard build

This folder contains the Vite source for the NetSentry React dashboard. From this directory, install dependencies and build the bundled assets:

```powershell
npm install
npm run build
```

The build writes static files to `src/netsentry/dashboard/`; Python packages these files with the API. Node.js is needed to build the UI, not to run it on the Raspberry Pi.
