package ast

// ASTContext is the top-level struct passed to existing detectors.
// Available is false when AST analysis failed for a plugin.
type ASTContext struct {
	Resolver  *Resolver
	Available bool
}
