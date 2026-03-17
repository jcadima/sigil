<?php

declare(strict_types=1);

namespace Sigil\Rules;

use Countable;
use Iterator;

class FindingCollection implements Countable, Iterator
{
    /** @var Finding[] */
    private array $findings = [];
    private int   $position = 0;

    public function add(Finding $finding): void
    {
        $this->findings[] = $finding;
    }

    public function merge(self $other): void
    {
        foreach ($other->findings as $finding) {
            $this->findings[] = $finding;
        }
    }

    public function filterBySeverity(Severity $severity): self
    {
        $new = new self();
        foreach ($this->findings as $f) {
            if ($f->severity === $severity) {
                $new->add($f);
            }
        }
        return $new;
    }

    public function filterByCategory(string $category): self
    {
        $new = new self();
        foreach ($this->findings as $f) {
            if (strtolower($f->category) === strtolower($category)) {
                $new->add($f);
            }
        }
        return $new;
    }

    public function filterAutoFixable(): self
    {
        $new = new self();
        foreach ($this->findings as $f) {
            if ($f->canAutoFix) {
                $new->add($f);
            }
        }
        return $new;
    }

    public function isEmpty(): bool
    {
        return empty($this->findings);
    }

    public function calculateScore(): int
    {
        $score = 100;
        foreach ($this->findings as $f) {
            $score -= $f->severity->scoreDeduction();
        }
        return max(0, $score);
    }

    /** @return Finding[] */
    public function all(): array
    {
        return $this->findings;
    }

    public function toArray(): array
    {
        return array_map(fn(Finding $f) => [
            'rule_id'    => $f->ruleId,
            'severity'   => $f->severity->value,
            'file'       => $f->file,
            'line'       => $f->line,
            'message'    => $f->message,
            'category'   => $f->category,
            'can_fix'    => $f->canAutoFix,
            'remediation' => [
                'instructions' => $f->remediation->instructions,
                'patch_ref'    => $f->remediation->patchRef,
                'manual_steps' => $f->remediation->manualSteps,
            ],
        ], $this->findings);
    }

    // Countable
    public function count(): int
    {
        return count($this->findings);
    }

    // Iterator
    public function current(): Finding
    {
        return $this->findings[$this->position];
    }

    public function key(): int
    {
        return $this->position;
    }

    public function next(): void
    {
        $this->position++;
    }

    public function rewind(): void
    {
        $this->position = 0;
    }

    public function valid(): bool
    {
        return isset($this->findings[$this->position]);
    }
}
