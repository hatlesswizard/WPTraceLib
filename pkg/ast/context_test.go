package ast

import "testing"

func TestASTContextDefault(t *testing.T) {
	ctx := &ASTContext{}
	if ctx.Available {
		t.Error("default ASTContext should have Available=false")
	}
	if ctx.Resolver != nil {
		t.Error("default ASTContext should have nil Resolver")
	}
}

func TestASTContextWithResolver(t *testing.T) {
	r := &Resolver{}
	ctx := &ASTContext{Resolver: r, Available: true}
	if !ctx.Available {
		t.Error("ASTContext with resolver should have Available=true")
	}
	if ctx.Resolver != r {
		t.Error("ASTContext.Resolver should match")
	}
}
