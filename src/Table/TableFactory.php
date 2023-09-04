<?php
namespace Ltlacerda\Iptables\Table;

/**
 * Class TableFactory
 * @package Ltlacerda\Iptables\Table
 */
class TableFactory
{
    /**
     * @param string $name
     * @return FilterTable|MangleTable|NatTable|RawTable|SecurityTable
     * @throws \Exception
     */
    public static function create($name)
    {
        switch ($name) {
            case Table::TABLE_FILTER :
                return new FilterTable();
            case Table::TABLE_MANGLE :
                return new MangleTable();
            case Table::TABLE_NAT :
                return new NatTable();
            case Table::TABLE_RAW :
                return new RawTable();
            case Table::TABLE_SECURITY :
                return new SecurityTable();
            default :
                throw new \Exception('Not found!');
        }
    }

    /**
     * @param string $name
     * @return FilterTable|MangleTable|NatTable|RawTable|SecurityTable
     * @throws \Exception
     * @deprecated Use TableFactory::create($name)
     */
    public function build($name)
    {
        return static::create($name);
    }
}