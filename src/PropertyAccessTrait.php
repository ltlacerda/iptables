<?php
namespace Azurre\Iptables;

trait PropertyAccessTrait
{
    public function __get($name)
    {
        return property_exists($this, $name) ? $this->{$name} : null;
    }

    public function __set($name, $value)
    {
        if (property_exists($this, $name)) {
            $setter = 'set' . ucfirst($name);
            if (method_exists($this, $setter)) {
                $this->{$setter}($value);
            } else {
                $this->{$name} = $value;
            }
            return;
        }
        throw new \InvalidArgumentException("Property {$name} does not exists");
    }
}