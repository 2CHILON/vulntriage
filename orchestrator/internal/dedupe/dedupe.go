package dedupe

import (
	"fmt"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// Group represents a cluster of duplicate findings.
type Group struct {
	ID                      string
	Findings                []*model.Finding
	Representative          *model.Finding
	StrategyUsed            string
	DeduplicatedCount       int
}

// Deduplicator groups findings and assigns canonical records.
type Deduplicator struct {
	strategy Strategy
}

// NewDeduplicator creates a new deduplicator with the given strategy.
func NewDeduplicator(strategy Strategy) *Deduplicator {
	return &Deduplicator{
		strategy: strategy,
	}
}

// NewDefaultDeduplicator creates a deduplicator with the default strategy.
func NewDefaultDeduplicator() *Deduplicator {
	return &Deduplicator{
		strategy: NewDefaultStrategy(),
	}
}

// Dedup groups findings into clusters of duplicates and returns groups with canonical findings.
func (d *Deduplicator) Dedup(findings []*model.Finding) []*Group {
	if len(findings) == 0 {
		return nil
	}

	// Group findings by matching strategy
	groups := make([]*Group, 0)
	used := make(map[int]bool)

	for i := 0; i < len(findings); i++ {
		if used[i] {
			continue
		}

		// Start a new group
		group := &Group{
			ID:           fmt.Sprintf("group-%s", findings[i].ID),
			Findings:     []*model.Finding{findings[i]},
			StrategyUsed: d.strategy.Name(),
		}
		used[i] = true

		// Find all findings that match this one
		for j := i + 1; j < len(findings); j++ {
			if used[j] {
				continue
			}

			if d.strategy.Match(findings[i], findings[j]) {
				group.Findings = append(group.Findings, findings[j])
				used[j] = true
			}
		}

		// Select the best finding as the representative (canonical)
		group.selectRepresentative()
		group.DeduplicatedCount = len(group.Findings) - 1

		groups = append(groups, group)
	}

	return groups
}

// selectRepresentative chooses the best finding in the group as the canonical one.
func (g *Group) selectRepresentative() {
	if len(g.Findings) == 0 {
		return
	}

	best := g.Findings[0]
	bestScore := g.priority(best)

	for _, f := range g.Findings[1:] {
		score := g.priority(f)
		if score > bestScore {
			best = f
			bestScore = score
		}
	}

	g.Representative = best
}

// priority returns the priority score for a finding (used in selection).
func (g *Group) priority(f *model.Finding) int {
	score := 0

	// CVE is highest priority
	if f.CVE != "" {
		score += 1000
	}

	// CWE is secondary
	if f.CWE != "" {
		score += 500
	}

	// Source priority
	switch f.Source {
	case "trivy":
		score += 300
	case "semgrep":
		score += 200
	case "zap":
		score += 100
	case "depcheck":
		score += 50
	}

	// Prefer longer descriptions (more detail)
	score += len(f.Description) / 10

	return score
}

// Mark applies deduplication results to findings by setting group IDs and canonical flags.
func (d *Deduplicator) Mark(findings []*model.Finding, groups []*Group) {
	// Create a map from finding ID to its group
	findingToGroup := make(map[string]*Group)
	for _, g := range groups {
		for _, f := range g.Findings {
			findingToGroup[f.ID] = g
		}
	}

	// Mark all findings with their group and canonical status
	for _, f := range findings {
		g, found := findingToGroup[f.ID]
		if !found {
			continue
		}

		// All findings in group get the group ID
		f.DedupeGroupID = g.ID

		// Only the representative is canonical
		if f.ID == g.Representative.ID {
			f.IsCanonical = true
		} else {
			f.IsCanonical = false
		}

		// Set the reason for non-canonical findings
		if f.ID != g.Representative.ID {
			f.DedupeReason = fmt.Sprintf("deduplicated with %s (via %s)",
				g.Representative.ID, d.strategy.Name())
		}
	}
}

// Stats provides deduplication statistics.
type Stats struct {
	TotalFindings    int
	GroupsCreated    int
	DuplicatesRemoved int
	CanonicalFindings int
}

// GetStats returns statistics about deduplication results.
func GetStats(groups []*Group) Stats {
	totalFindings := 0
	duplicatesRemoved := 0

	for _, g := range groups {
		totalFindings += len(g.Findings)
		duplicatesRemoved += g.DeduplicatedCount
	}

	return Stats{
		TotalFindings:     totalFindings,
		GroupsCreated:     len(groups),
		DuplicatesRemoved:  duplicatesRemoved,
		CanonicalFindings: len(groups),
	}
}
