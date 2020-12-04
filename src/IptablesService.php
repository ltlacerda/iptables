<?php
namespace azurre\iptables;

use azurre\iptables\Table\Table;

/**
 * Class Iptables
 */
class IptablesService
{
    /**
     * @var Table[]
     */
    private $tables;

    /**
     * Iptables constructor.
     */
    public function __construct()
    {
    }

    /**
     * Parse raw iptables data into objects.
     * $rawData is a raw dump of: `iptables -nL --line-numbers -t TABLENAME`
     *
     * @param Table $table
     * @return Chain[]
     */
    public function parseIptablesChains(Table $table)
    {
        $data = explode("\n", $table->getRaw());

        $patterns = [
            'chain' => '/(?:Chain\s)
                        (?<chain>[^\s]+)
                        (?:.*\()
                        (?<policy>.*)
                        (?:\).*)/x',

            'rule' => '/(?<num>\d+)\s+
                        (?<packets>\d+)\s+
                        (?<bytes>\d+)\s+
                        (?<target>\w+)\s+
                        (?<protocol>\w+)\s+
                        (?<opt>[\w-]+)\s+
                        (?<in>[\w+\*]+)\s+
                        (?<out>[\w+\*]+)\s+
                        (?<source>[0-9\.\/]+)\s+
                        (?<destination>[0-9\.\/]+)\s+
                        ?(?<options>.*)/x'
        ];

        foreach ($data as $row) {
            if (preg_match($patterns['chain'], $row, $out)) {
                $chain = new Chain($out['chain'], $table->getName(), $out['policy']);
                $table->addChain($chain);
                $this->tables[$table->getName()] = $table;
            }

            if (isset($chain) && preg_match($patterns['rule'], $row, $out)) {
                $rule = Rule::create($out);
                $chain->insertRule($rule, $out['num']);
            }
        }

        return $table->getChainsList();
    }
}