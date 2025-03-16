group "default" {
  targets = ["threats-scanner"]
}

target "threats-scanner" {
  tags = ["ghcr.io/testdotcom/threats-scanner:latest"]
}
