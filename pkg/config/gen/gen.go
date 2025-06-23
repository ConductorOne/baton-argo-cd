package main

import (
	cfg "github.com/conductorone/baton-argo-cd/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("argo-cd", cfg.Config)
}
