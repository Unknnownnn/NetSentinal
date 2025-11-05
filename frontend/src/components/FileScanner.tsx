import React, { useState } from 'react';

interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
}

interface FileHashResponse {
  filename: string;
  size: number;
  hashes: FileHashes;
  error?: string;
}

interface VirusTotalReport {
  file_id: string;
  scan_date?: number;
  stats?: {
    malicious: number;
    suspicious: number;
    undetected: number;
    harmless: number;
    timeout: number;
    'confirmed-timeout': number;
    failure: number;
    'type-unsupported': number;
  };
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  total_scans: number;
  detection_ratio: string;
  engines?: Record<string, any>;
  file_info?: {
    size: number;
    type: string;
    magic: string;
    md5: string;
    sha1: string;
    sha256: string;
    names: string[];
  };
  permalink?: string;
  status?: string;
  message?: string;
  suggestion?: string;
  error?: string;
}

export default function FileScanner() {
  const [apiKey, setApiKey] = useState<string>(() => localStorage.getItem('vt_api_key') || '');
  const [file, setFile] = useState<File | null>(null);
  const [hashes, setHashes] = useState<FileHashes | null>(null);
  const [result, setResult] = useState<VirusTotalReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<'setup' | 'select' | 'hash' | 'report'>(() => {
    const savedKey = localStorage.getItem('vt_api_key');
    return savedKey && savedKey.trim() ? 'select' : 'setup';
  });

  function saveApiKey(key: string) {
    localStorage.setItem('vt_api_key', key);
    setApiKey(key);
    if (key.trim()) {
      setStep('select');
    }
  }

  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    setFile(f);
    setResult(null);
    setHashes(null);
    if (step !== 'setup') {
      setStep('select');
    }
  }

  async function calculateHashes() {
    if (!file) return;
    setLoading(true);
    
    try {
      const form = new FormData();
      form.append('file', file);

      const resp = await fetch('/api/security/hash-file', {
        method: 'POST',
        body: form
      });

      if (!resp.ok) {
        throw new Error(`Failed to calculate hashes: ${resp.status}`);
      }

      const data: FileHashResponse = await resp.json();
      if (data.error) {
        throw new Error(data.error);
      }

      setHashes(data.hashes);
      setStep('hash');
    } catch (err) {
      console.error('Hash calculation error:', err);
      setResult({ error: String(err) } as VirusTotalReport);
    }
    
    setLoading(false);
  }

  async function lookupHash(hash: string) {
    if (!apiKey.trim()) {
      setResult({ error: 'Please enter your VirusTotal API key' } as VirusTotalReport);
      return;
    }
    
    setLoading(true);
    setResult(null);
    
    try {
      const url = `/api/security/virustotal-report/${hash}?api_key=${encodeURIComponent(apiKey)}`;
      
      const resp = await fetch(url);

      if (!resp.ok) {
        throw new Error(`VirusTotal lookup failed: ${resp.status}`);
      }

      const data: VirusTotalReport = await resp.json();
      setResult(data);
      setStep('report');
    } catch (err) {
      console.error('Hash lookup error:', err);
      setResult({ error: String(err) } as VirusTotalReport);
    }
    
    setLoading(false);
  }

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getThreatLevel = (report: VirusTotalReport): { level: string; color: string; description: string } => {
    if (report.error || report.status === 'not_found') {
      return { level: 'Unknown', color: '#6b7280', description: 'File not found in database' };
    }

    const malicious = report.malicious || 0;
    const suspicious = report.suspicious || 0;
    const total = report.total_scans || 0;

    if (malicious > 0) {
      if (malicious >= 5) {
        return { level: 'High Risk', color: '#dc2626', description: `${malicious} engines detected as malicious` };
      }
      return { level: 'Medium Risk', color: '#f59e0b', description: `${malicious} engines detected as malicious` };
    }

    if (suspicious > 0) {
      return { level: 'Suspicious', color: '#f59e0b', description: `${suspicious} engines flagged as suspicious` };
    }

    if (total > 0) {
      return { level: 'Clean', color: '#16a34a', description: 'No threats detected' };
    }

    return { level: 'Unknown', color: '#6b7280', description: 'No scan data available' };
  };

  return (
    <div className="mx-auto p-6 bg-slate-900 rounded-xl shadow-lg border border-gray-700 hover:shadow-xl transition">
      <div className="mb-6">
        <h3 className="text-xl font-bold mb-2 text-blue-400">VirusTotal File Scanner</h3>
        <p className="text-gray-400 text-sm">Check files for malware using hash-based lookups (recommended by VirusTotal)</p>
      </div>

      {/* Step 0: API Key Setup */}
      {step === 'setup' && (
        <div className="mb-6 p-4 rounded-lg border border-yellow-500 bg-yellow-900/20">
          <h4 className="text-lg font-semibold mb-3 text-white">🔑 Setup Required</h4>
          <p className="text-gray-300 mb-4">
            You need a VirusTotal API key to use this scanner. Don't have one?{' '}
            <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 underline">
              Get your free API key here
            </a>
          </p>
          
          <label className="block mb-4 text-gray-300">
            <span className="text-sm font-medium">VirusTotal API Key</span>
            <input
              className="border border-gray-600 bg-gray-700 text-white rounded-lg p-3 w-full mt-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              type="password"
              value={apiKey}
              onChange={(e) => saveApiKey(e.target.value)}
              placeholder="Enter your VirusTotal API key"
              autoFocus
            />
            <p className="text-xs text-gray-400 mt-2">
              Your API key will be stored locally in your browser for future use.
            </p>
          </label>

          <div className="flex items-center gap-3 mt-4">
            {apiKey.trim() && (
              <div className="flex items-center text-green-400">
                <span className="mr-2">✅</span>
                <span className="text-sm">API key saved! You can now scan files.</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Step 1: File Selection */}
      {step !== 'setup' && (
        <div className={`mb-6 p-4 rounded-lg border ${step === 'select' ? 'border-blue-500 bg-blue-900/20' : step === 'hash' || step === 'report' ? 'border-green-500 bg-green-900/20' : 'border-gray-600'}`}>
          <h4 className="text-lg font-semibold mb-3 text-white">
            1. Select File
            {apiKey && (
              <button
                onClick={() => setStep('setup')}
                className="ml-2 text-xs text-blue-400 hover:text-blue-300"
                title="Change API key"
              >
                (Change API Key)
              </button>
            )}
          </h4>
        
        <label className="block mb-4 text-gray-300">
          <span className="text-sm font-medium">Choose file to analyze</span>
          <input
            type="file"
            onChange={handleFileChange}
            className="block mt-1 text-sm text-gray-400 w-full
                    file:mr-4 file:py-2 file:px-4
                    file:rounded-full file:border-0
                    file:text-sm file:font-semibold
                    file:bg-blue-500 file:text-white
                    hover:file:bg-blue-600
                    cursor-pointer"
          />
        </label>

        {file && (
          <div className="mb-3 p-3 bg-gray-800 rounded-lg text-gray-300 text-sm">
            <div><strong>Filename:</strong> {file.name}</div>
            <div><strong>Size:</strong> {formatBytes(file.size)}</div>
            <div><strong>Type:</strong> {file.type || 'Unknown'}</div>
          </div>
        )}

        <button 
          onClick={calculateHashes}
          disabled={!file || loading}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg shadow transition"
        >
          {loading ? 'Calculating...' : 'Calculate Hashes'}
        </button>
      </div>
      )}

      {/* Step 2: File Hashes */}
      {hashes && (
        <div className={`mb-6 p-4 rounded-lg border ${step === 'hash' ? 'border-blue-500 bg-blue-900/20' : step === 'report' ? 'border-green-500 bg-green-900/20' : 'border-gray-600'}`}>
          <h4 className="text-lg font-semibold mb-3 text-white">2. File Hashes</h4>
          
          <div className="space-y-2 mb-4">
            <div className="flex items-center justify-between bg-gray-800 p-2 rounded">
              <span className="text-gray-300 text-sm">MD5:</span>
              <div className="flex items-center gap-2">
                <code className="text-xs text-gray-200 bg-gray-700 px-2 py-1 rounded">{hashes.md5}</code>
                <button 
                  onClick={() => copyToClipboard(hashes.md5)}
                  className="text-xs text-blue-400 hover:text-blue-300"
                  title="Copy MD5"
                >
                  📋
                </button>
              </div>
            </div>
            
            <div className="flex items-center justify-between bg-gray-800 p-2 rounded">
              <span className="text-gray-300 text-sm">SHA-1:</span>
              <div className="flex items-center gap-2">
                <code className="text-xs text-gray-200 bg-gray-700 px-2 py-1 rounded">{hashes.sha1}</code>
                <button 
                  onClick={() => copyToClipboard(hashes.sha1)}
                  className="text-xs text-blue-400 hover:text-blue-300"
                  title="Copy SHA-1"
                >
                  📋
                </button>
              </div>
            </div>
            
            <div className="flex items-center justify-between bg-gray-800 p-2 rounded">
              <span className="text-gray-300 text-sm">SHA-256:</span>
              <div className="flex items-center gap-2">
                <code className="text-xs text-gray-200 bg-gray-700 px-2 py-1 rounded">{hashes.sha256}</code>
                <button 
                  onClick={() => copyToClipboard(hashes.sha256)}
                  className="text-xs text-blue-400 hover:text-blue-300"
                  title="Copy SHA-256"
                >
                  📋
                </button>
              </div>
            </div>
          </div>

          <label className="block mb-4 text-gray-300">
            <span className="text-sm font-medium">VirusTotal API Key</span>
            <input
              className="border border-gray-600 bg-gray-700 text-white rounded-lg p-2 w-full mt-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
              type="password"
              value={apiKey}
              onChange={(e) => saveApiKey(e.target.value)}
              placeholder="Enter your VirusTotal API key" 
            />
            <p className="text-xs text-gray-400 mt-1">
              Get your free API key from <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300">VirusTotal</a>
            </p>
          </label>

          <div className="flex flex-wrap gap-2">
            <button 
              onClick={() => lookupHash(hashes.md5)}
              disabled={!apiKey.trim() || loading}
              className="px-3 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg shadow transition text-sm"
            >
              {loading ? 'Checking...' : 'Check MD5'}
            </button>
            <button 
              onClick={() => lookupHash(hashes.sha1)}
              disabled={!apiKey.trim() || loading}
              className="px-3 py-2 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg shadow transition text-sm"
            >
              {loading ? 'Checking...' : 'Check SHA-1'}
            </button>
            <button 
              onClick={() => lookupHash(hashes.sha256)}
              disabled={!apiKey.trim() || loading}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg shadow transition text-sm font-semibold"
            >
              {loading ? 'Checking...' : 'Check SHA-256 (Recommended)'}
            </button>
          </div>
        </div>
      )}

      {/* Step 3: VirusTotal Report */}
      {result && (
        <div className="p-4 rounded-lg border border-blue-500 bg-blue-900/20">
          <h4 className="text-lg font-semibold mb-3 text-white">3. VirusTotal Report</h4>
          
          {result.error ? (
            <div className="bg-red-900/30 border border-red-500 rounded-lg p-4 mb-4">
              <h5 className="text-red-400 font-semibold mb-2">Error</h5>
              <p className="text-gray-300">{result.error}</p>
            </div>
          ) : result.status === 'not_found' ? (
            <div className="bg-yellow-900/30 border border-yellow-500 rounded-lg p-4 mb-4">
              <h5 className="text-yellow-400 font-semibold mb-2">File Not Found</h5>
              <p className="text-gray-300 mb-2">{result.message}</p>
              {result.suggestion && <p className="text-gray-400 text-sm">{result.suggestion}</p>}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="text-center p-4 rounded-lg" style={{ backgroundColor: getThreatLevel(result).color + '20', borderColor: getThreatLevel(result).color, borderWidth: '1px' }}>
                <div 
                  className="inline-block px-4 py-2 rounded-full text-white font-bold text-lg"
                  style={{ backgroundColor: getThreatLevel(result).color }}
                >
                  {getThreatLevel(result).level}
                </div>
                <p className="text-gray-300 mt-2">{getThreatLevel(result).description}</p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h5 className="text-white font-semibold mb-3">Scan Statistics</h5>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  <div className="bg-red-900/50 p-3 rounded">
                    <div className="text-2xl font-bold text-red-400">{result.malicious}</div>
                    <div className="text-xs text-gray-300">Malicious</div>
                  </div>
                  <div className="bg-yellow-900/50 p-3 rounded">
                    <div className="text-2xl font-bold text-yellow-400">{result.suspicious}</div>
                    <div className="text-xs text-gray-300">Suspicious</div>
                  </div>
                  <div className="bg-gray-700 p-3 rounded">
                    <div className="text-2xl font-bold text-gray-400">{result.undetected}</div>
                    <div className="text-xs text-gray-300">Undetected</div>
                  </div>
                  <div className="bg-green-900/50 p-3 rounded">
                    <div className="text-2xl font-bold text-green-400">{result.harmless}</div>
                    <div className="text-xs text-gray-300">Harmless</div>
                  </div>
                </div>
                <div className="mt-3 text-center">
                  <span className="text-white font-semibold">Detection Ratio: {result.detection_ratio}</span>
                </div>
              </div>

              {result.file_info && (
                <div className="bg-gray-800 rounded-lg p-4">
                  <h5 className="text-white font-semibold mb-3">File Details</h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                    <div className="text-gray-300"><strong>Size:</strong> {formatBytes(result.file_info.size)}</div>
                    <div className="text-gray-300"><strong>Type:</strong> {result.file_info.type}</div>
                    {result.scan_date && (
                      <div className="text-gray-300 md:col-span-2"><strong>Last Scanned:</strong> {formatDate(result.scan_date)}</div>
                    )}
                  </div>
                </div>
              )}

              {result.engines && Object.keys(result.engines).length > 0 && (
                <div className="bg-gray-800 rounded-lg p-4">
                  <h5 className="text-white font-semibold mb-3">Top Antivirus Engine Results</h5>
                  <div className="max-h-40 overflow-y-auto space-y-1">
                    {Object.entries(result.engines).slice(0, 10).map(([engine, engineResult]: [string, any]) => (
                      <div key={engine} className={`flex justify-between items-center text-sm p-2 rounded ${
                        engineResult.category === 'malicious' ? 'bg-red-900/30' : 
                        engineResult.category === 'suspicious' ? 'bg-yellow-900/30' : 
                        'bg-gray-700'
                      }`}>
                        <span className="text-gray-300">{engine}</span>
                        <span className={`font-semibold ${
                          engineResult.category === 'malicious' ? 'text-red-400' : 
                          engineResult.category === 'suspicious' ? 'text-yellow-400' : 
                          'text-green-400'
                        }`}>
                          {engineResult.result || engineResult.category || 'Clean'}
                        </span>
                      </div>
                    ))}
                  </div>
                  {Object.keys(result.engines).length > 10 && (
                    <p className="text-xs text-gray-400 mt-2">Showing first 10 of {Object.keys(result.engines).length} engines</p>
                  )}
                </div>
              )}

              {result.permalink && (
                <div className="text-center">
                  <a 
                    href={result.permalink} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="inline-block px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg shadow transition"
                  >
                    View Full Report on VirusTotal
                  </a>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
