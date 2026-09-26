import puppeteer from "puppeteer";

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  
  page.on('pageerror', err => {
    console.log("PAGE ERROR:", err.message);
  });
  
  page.on('console', msg => {
    if (msg.type() === 'error') {
      console.log("CONSOLE ERROR:", msg.text());
    }
  });

  await page.goto("http://localhost:5173", { waitUntil: 'networkidle2' });
  
  // Set token
  await page.evaluate(() => {
    localStorage.setItem('token', 'dummy');
  });
  
  // To avoid real auth, let's just intercept the API call and return the real response I fetched earlier!
  await page.setRequestInterception(true);
  page.on('request', request => {
    const url = request.url();
    if (url.includes('/api/v1/investigations/09130555-5067-4593-bbc5-a9d41dfc4a21/score')) {
      request.respond({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({"id":"d79c07de-0897-4934-a3bd-675385e54c81","investigation_id":"09130555-5067-4593-bbc5-a9d41dfc4a21","analysis_run_id":"3ce01ab4-fa55-4b91-9cbd-75a988702c9a","total_score":0,"severity":"LOW","verdict":"SUSPICIOUS","category_breakdown":{},"triggered_floor_codes":[]})
      });
    } else if (url.includes('/api/v1/investigations/09130555-5067-4593-bbc5-a9d41dfc4a21')) {
      request.continue(); // Let it hit the real backend
    } else {
      request.continue();
    }
  });
  
  // Instead of full flow, let's just manually trigger setSelectedId
  await page.evaluate(() => {
    window.location.hash = ""; // just to be sure
  });
  
  // Wait, I can just let the real backend handle it!
  // The backend is running on 8081 or 8000. Wait, the frontend proxies to 8000.
  // Assuming the user's backend is on 8000. 
  // Wait, the user already uploaded it, so we can just load the list and click the first item!
  await page.goto("http://localhost:5173", { waitUntil: 'networkidle0' });
  
  // Wait for the investigation list to load
  await new Promise(r => setTimeout(r, 2000));
  
  console.log("Done waiting");
  await browser.close();
})();
