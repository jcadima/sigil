<?php

declare(strict_types=1);

namespace Sigil\Parsers;

class NginxParser implements ParserInterface
{
    private int    $pos    = 0;
    private array  $tokens = [];
    private string $baseDir = '';

    public function parse(string $path): NginxConfig
    {
        if (!file_exists($path)) {
            return new NginxConfig();
        }

        $this->baseDir = dirname($path);
        $content       = $this->readAndStripComments($path);
        $this->tokens  = $this->tokenize($content);
        $this->pos     = 0;

        $tree = $this->parseBlock();

        return new NginxConfig($tree);
    }

    private function readAndStripComments(string $path): string
    {
        $lines  = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        $result = [];

        foreach ($lines as $line) {
            // Strip inline comments — but be careful not to strip # inside quoted strings
            $stripped = preg_replace('/#[^\'"]*$/', '', $line);
            $result[] = $stripped ?? $line;
        }

        return implode("\n", $result);
    }

    private function tokenize(string $content): array
    {
        $tokens = [];
        $len    = strlen($content);
        $i      = 0;
        $buf    = '';

        while ($i < $len) {
            $ch = $content[$i];

            if ($ch === '{' || $ch === '}' || $ch === ';') {
                if ($buf !== '' && trim($buf) !== '') {
                    $tokens[] = trim($buf);
                    $buf      = '';
                }
                $tokens[] = $ch;
                $i++;
            } elseif ($ch === '"' || $ch === "'") {
                // Quoted string
                $quote = $ch;
                $i++;
                $qbuf = '';
                while ($i < $len && $content[$i] !== $quote) {
                    $qbuf .= $content[$i];
                    $i++;
                }
                $i++; // skip closing quote
                $buf .= $quote . $qbuf . $quote;
            } else {
                $buf .= $ch;
                $i++;
            }
        }

        if ($buf !== '' && trim($buf) !== '') {
            $tokens[] = trim($buf);
        }

        return $tokens;
    }

    /**
     * Parse a block of nginx config tokens into a structured array.
     * Stops at '}' or end of tokens.
     */
    private function parseBlock(): array
    {
        $node = ['blocks' => []];

        while ($this->pos < count($this->tokens)) {
            $token = $this->tokens[$this->pos];

            if ($token === '}') {
                $this->pos++;
                break;
            }

            if ($token === ';') {
                $this->pos++;
                continue;
            }

            // Collect directive tokens until { or ;
            $parts = $this->collectUntil(['{', ';', '}']);

            if (empty($parts)) {
                $this->pos++;
                continue;
            }

            $directive = $parts[0];
            $args      = array_slice($parts, 1);

            // Peek at current token
            $next = $this->tokens[$this->pos] ?? null;

            if ($next === '{') {
                $this->pos++; // consume {
                $child = $this->parseBlock();

                // Handle 'include' specially
                if ($directive === 'include') {
                    // Will be handled below
                }

                $key  = implode(' ', array_merge([$directive], $args));
                $type = $directive;

                // Extract location key
                $blockKey = null;
                if (!empty($args)) {
                    $blockKey = implode(' ', $args);
                    $child['_key'] = $blockKey;
                }

                if (!isset($node['blocks'][$type])) {
                    $node['blocks'][$type] = [];
                }
                $node['blocks'][$type][] = $child;

            } elseif ($next === ';') {
                $this->pos++; // consume ;

                $value = implode(' ', $args);

                if ($directive === 'include') {
                    // Expand includes
                    $this->handleInclude($value, $node);
                } else {
                    // Store directive; if duplicate, make array
                    if (isset($node[$directive])) {
                        if (!is_array($node[$directive])) {
                            $node[$directive] = [$node[$directive]];
                        }
                        $node[$directive][] = $value;
                    } else {
                        $node[$directive] = $value;
                    }
                }
            } else {
                // Unexpected — just skip
                $this->pos++;
            }
        }

        return $node;
    }

    private function collectUntil(array $stops): array
    {
        $parts = [];
        while ($this->pos < count($this->tokens)) {
            $tok = $this->tokens[$this->pos];
            if (in_array($tok, $stops, true)) {
                break;
            }
            // Split token on whitespace to handle multi-word tokens
            $words = preg_split('/\s+/', $tok, -1, PREG_SPLIT_NO_EMPTY);
            foreach ($words as $word) {
                $parts[] = $word;
            }
            $this->pos++;
        }
        return $parts;
    }

    private function handleInclude(string $pattern, array &$node): void
    {
        // Resolve relative paths
        if (!str_starts_with($pattern, '/')) {
            $pattern = $this->baseDir . '/' . $pattern;
        }

        $files = glob($pattern) ?: [];

        foreach ($files as $file) {
            if (!file_exists($file) || !is_readable($file)) {
                continue;
            }

            // Parse sub-file
            $subParser          = new self();
            $subParser->baseDir = dirname($file);
            $content            = $subParser->readAndStripComments($file);
            $subParser->tokens  = $subParser->tokenize($content);
            $subParser->pos     = 0;

            $subTree = $subParser->parseBlock();

            // Merge directives
            foreach ($subTree as $key => $value) {
                if ($key === 'blocks') {
                    foreach ($value as $blockType => $blocks) {
                        if (!isset($node['blocks'][$blockType])) {
                            $node['blocks'][$blockType] = [];
                        }
                        $node['blocks'][$blockType] = array_merge(
                            $node['blocks'][$blockType],
                            $blocks
                        );
                    }
                } else {
                    $node[$key] = $value;
                }
            }
        }
    }
}
