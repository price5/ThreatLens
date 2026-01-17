'use client';

import { useState } from 'react';
import jsQR from 'jsqr';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export function QRUploadForm({
  onDecodedUrl,
}: {
  onDecodedUrl: (url: string) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [decodedUrl, setDecodedUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const decodeQR = () => {
    if (!file) {
      setError('Please upload an image');
      return;
    }

    setError(null);
    setDecodedUrl(null);
    setLoading(true);

    const image = new Image();
    image.src = URL.createObjectURL(file);

    image.onload = () => {
      try {
        const canvas = document.createElement('canvas');
        canvas.width = image.width;
        canvas.height = image.height;

        const ctx = canvas.getContext('2d');
        if (!ctx) throw new Error('Canvas error');

        ctx.drawImage(image, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        const code = jsQR(
          imageData.data,
          imageData.width,
          imageData.height
        );

        if (!code) {
          setError('No QR code detected in image');
          setLoading(false);
          return;
        }

        // ✅ QR decoded URL
        setDecodedUrl(code.data);

        // 🔥 REUSE SAME LINK SCAN FUNCTION
        onDecodedUrl(code.data);
      } catch (err) {
        console.error(err);
        setError('QR decoding failed');
      } finally {
        setLoading(false);
      }
    };
  };

  return (
    <Card className="max-w-md mx-auto">
      <CardHeader>
        <CardTitle>Scan QR Code</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <Input
          type="file"
          accept="image/*"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />

        <Button onClick={decodeQR} className="w-full" disabled={loading}>
          {loading ? 'Decoding...' : 'Decode & Scan'}
        </Button>

        {decodedUrl && (
          <div className="text-sm text-green-500 break-all">
            <strong>Decoded URL:</strong>
            <br />
            {decodedUrl}
          </div>
        )}

        {error && (
          <p className="text-sm text-red-500">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
