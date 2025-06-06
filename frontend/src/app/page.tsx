// frontend/src/app/page.tsx
"use client";

import { useEffect, useState } from 'react';

export default function HomePage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchData() {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL;
        if (!apiUrl) {
          throw new Error("API URL is not configured");
        }
        // Example: Fetching from the backend's root health check
        const response = await fetch(`${apiUrl}/`);
        // Or from the /metrics endpoint:
        // const response = await fetch(`${apiUrl}/metrics`);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        setData(result);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, []);

  if (loading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;

  return (
    <div>
      <h1>SES Application Frontend</h1>
      <p>Data from backend:</p>
      <pre>{JSON.stringify(data, null, 2)}</pre>
      {/* Add other components like ScoreCard, FindingsList etc. here,
          passing the API_URL or fetched data as props if needed. */}
    </div>
  );
}
