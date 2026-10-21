<#
    03-Serve-Metrics.ps1
    Espone C:\ProgramData\ADMonitor\metrics.prom su HTTP (porta 9182) per Prometheus.
    Gira come SYSTEM, task "at startup".
#>
[CmdletBinding()]
param(
    [int]$Port = 9182,
    [string]$MetricsPath = 'C:\ProgramData\ADMonitor\metrics.prom'
)

$ErrorActionPreference = 'Continue'

if (-not ('ADMonitor.Listener' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Text;
using System.IO;
using System.Threading;

namespace ADMonitor {
    public class Listener : IDisposable {
        private readonly HttpListener _http = new HttpListener();
        private readonly string _path;
        private readonly string _prefix;
        private volatile bool _running = true;

        public Listener(int port, string path) {
            _path = path;
            _prefix = string.Format("http://+:{0}/", port);
            _http.Prefixes.Add(_prefix);
            _http.Start();
            ThreadPool.QueueUserWorkItem(delegate { Loop(); });
        }

        private void Loop() {
            while (_running) {
                try {
                    var ctx = _http.GetContext();
                    var res = ctx.Response;
                    if (ctx.Request.Url.AbsolutePath == "/metrics" || ctx.Request.Url.AbsolutePath == "/") {
                        byte[] body;
                        try {
                            body = File.ReadAllBytes(_path);
                            res.StatusCode = 200;
                            res.ContentType = "text/plain; version=0.0.4; charset=utf-8";
                        } catch {
                            body = Encoding.UTF8.GetBytes("# AD collector: no data yet\n");
                            res.StatusCode = 503;
                            res.ContentType = "text/plain; charset=utf-8";
                        }
                        res.ContentLength64 = body.Length;
                        res.OutputStream.Write(body, 0, body.Length);
                        res.OutputStream.Close();
                    } else {
                        res.StatusCode = 404;
                        res.Close();
                    }
                } catch (Exception ex) {
                    try { Console.Error.WriteLine(ex.Message); } catch { }
                    Thread.Sleep(2000);
                }
            }
        }

        public void Dispose() {
            _running = false;
            try { _http.Stop(); _http.Close(); } catch { }
        }
    }
}
'@ -ReferencedAssemblies System.Net.Http
}

Write-Host "AD metrics listener starting on port $Port ..."
$listener = New-Object ADMonitor.Listener($Port, $MetricsPath)
Write-Host "Serving $MetricsPath at http://0.0.0.0:$Port/metrics"
try {
    while ($true) { Start-Sleep -Seconds 3600 }
} finally {
    $listener.Dispose()
}
