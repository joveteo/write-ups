# Evidence files still to copy from the Ubuntu sensor VM (`~/evidence/`)

These are referenced (with SHA-256) in `../incident-report.md` §12 but live only
on the sensor VM. Copy them into this `evidence/` folder before publishing:

- eve-alerts-hydra.json
- eve-alerts-nmap.json
- eve-alerts-web.json
- ssh-auth.log
- fast.log
- local.rules   (same as ../rules/local.rules; kept for the hashed bundle)
- SHA256SUMS

Verify after copying:  `cd evidence && sha256sum -c SHA256SUMS`
