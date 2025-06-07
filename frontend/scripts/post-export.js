const fs = require("fs");
const path = require("path");
const { globSync } = require("glob"); // For glob v9+

const outDir = path.join(__dirname, "../out");
// Process HTML, JS, CSS, and TXT files. TXT is included for files like Next.js's flight data (e.g., index.txt).
const filesToProcess = globSync(`${outDir}/**/*.{html,js,css,txt}`);

console.log(
  `Processing ${filesToProcess.length} files in ${outDir} for path patching.`
);

filesToProcess.forEach((filePath) => {
  let content = fs.readFileSync(filePath, "utf8");
  const originalContent = content;

  // Phase 1: Specific HTML/CSS attributes (href, src, content for meta tags) and CSS url()
  // Replace paths starting with /_next/
  content = content.replace(
    /(href="|src="|content="|url\(")\/_next\//g,
    "$1./_next/"
  );
  // Replace paths for /favicon.ico
  content = content.replace(/(href="|src=")\/favicon\.ico/g, "$1./favicon.ico");

  // Phase 2: Quoted strings (common in JS, JSON, and Next.js data files like index.txt)
  // This targets "/_next/" when it's inside double quotes.
  content = content.replace(/"\/_next\//g, '"./_next/');
  content = content.replace(/"\/favicon\.ico"/g, '"./favicon.ico"');

  // Phase 3: For unquoted paths in specific structures (e.g., array in index.txt :HL["/_next/..."])
  // This targets ["/_next/" (an array starting with a path string)
  content = content.replace(/\["\/_next\//g, '["./_next/');
  // This targets [:"/_next/" (less common, but for safety)
  content = content.replace(/\[:"\/_next\//g, '[:"./_next/');

  if (originalContent !== content) {
    fs.writeFileSync(filePath, content, "utf8");
    console.log(
      `Patched: ${path.relative(path.join(__dirname, ".."), filePath)}`
    );
  }
});

console.log("Path patching complete.");
