<?php

declare(strict_types=1);

namespace Sigil\Rules\Docker;

use Sigil\Engine\ScanContext;
use Sigil\Rules\AbstractRule;
use Sigil\Rules\FindingCollection;
use Sigil\Rules\Remediation;
use Sigil\Rules\Severity;

class LatestTagUsedRule extends AbstractRule
{
    public function evaluate(ScanContext $context): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($context->docker->getServices() as $name => $svc) {
            $image = $context->docker->getImage($name);
            if ($image === null) {
                continue;
            }

            // Check for :latest or no tag
            $hasTag       = str_contains($image, ':');
            $isLatest     = $hasTag && str_ends_with($image, ':latest');
            $hasNoTag     = !$hasTag;

            if ($isLatest || $hasNoTag) {
                $collection->add($this->finding(
                    'D003',
                    Severity::MEDIUM,
                    $context->dockerComposePath ?? 'docker-compose.yml',
                    0,
                    sprintf(
                        'Service "%s" uses image "%s" without a specific version tag. Builds are not reproducible.',
                        $name,
                        $image,
                    ),
                    'docker',
                    new Remediation(
                        'Pin image to a specific version tag (e.g., nginx:1.25.3).',
                        null,
                        ['Change image: ' . $image . ' to image: ' . explode(':', $image)[0] . ':X.Y.Z'],
                    ),
                ));
            }
        }

        return $collection;
    }

    public function getSeverity(): Severity
    {
        return Severity::MEDIUM;
    }

    public function getCategory(): string
    {
        return 'docker';
    }

    public function getRemediation(): Remediation
    {
        return new Remediation('Pin Docker image tags to specific versions, not latest.');
    }
}
