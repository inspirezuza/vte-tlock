import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'edge'; // Optional: Use Edge runtime for speed

export async function GET(req: NextRequest, { params }: { params: Promise<{ slug: string[] }> }) {
    // Reconstruct the path from the slug (e.g., ["52db...", "info"] -> "52db.../info")
    const { slug } = await params;
    const path = slug.join('/');
    
    // Default to mainnet, but could be configurable via query param or env
    // For now, we proxy strictly to api.drand.sh
    const targetUrl = `https://api.drand.sh/${path}`;
    
    try {
        // Forward the request to Drand
        const response = await fetch(targetUrl, {
            headers: {
                // Pass meaningful headers if needed, mostly Accept
                'Accept': req.headers.get('Accept') || 'application/json',
            }
        });

        // Get the response body as ArrayBuffer to handle both JSON and binary (beacons)
        const body = await response.arrayBuffer();

        // Prepare response headers
        const headers = new Headers();
        const contentType = response.headers.get('Content-Type');
        if (contentType) {
            headers.set('Content-Type', contentType);
        }
        
        // Cache-Control is important for immutable beacons
        const cacheControl = response.headers.get('Cache-Control');
        if (cacheControl) {
            headers.set('Cache-Control', cacheControl);
        } else {
             // Default caching for safety
            headers.set('Cache-Control', 'public, max-age=60');
        }

        return new NextResponse(body, {
            status: response.status,
            statusText: response.statusText,
            headers: headers,
        });

    } catch (error: any) {
        console.error(`[DrandProxy] Error fetching ${targetUrl}:`, error);
        return NextResponse.json(
            { error: "Failed to proxy request check server logs" },
            { status: 502 }
        );
    }
}
