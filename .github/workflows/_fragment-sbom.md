# SBOM + scan job (pasted into pr-validate.yml and release.yml)

```yaml
  sbom-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
      - name: Generate CycloneDX SBOM
        uses: anchore/sbom-action@df80a981bc6edbc4e220a492d3cbe9f5547a6e75 # v0.17.9
        with:
          path: .
          format: cyclonedx-json
          output-file: sbom.cdx.json
      - name: Generate SPDX SBOM
        uses: anchore/sbom-action@df80a981bc6edbc4e220a492d3cbe9f5547a6e75 # v0.17.9
        with:
          path: .
          format: spdx-json
          output-file: sbom.spdx.json
      - name: Grype scan (gate High/Critical) from the SBOM
        uses: anchore/scan-action@abae793926ec39a78ab18002bc7fc45bbbd94342 # v6.0.0
        with:
          sbom: sbom.cdx.json
          fail-build: true
          severity-cutoff: high
      - name: Trivy config scan (IaC misconfig)
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0 # 0.29.0
        with:
          scan-type: config
          scan-ref: .
          trivy-config: trivy.yaml
      - name: Upload SBOMs
        uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
        with:
          name: sbom
          path: |
            sbom.cdx.json
            sbom.spdx.json
```
