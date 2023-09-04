<?php

namespace Ltlacerda\Iptables;

trait PropertyAccessTrait
{
    public function __get($name)
    {
        if (property_exists($this, $name)) {
            $getter = 'get' . ucfirst($name);
            return method_exists($this, $getter) ? $this->{$getter}() : $this->{$name};
        }
        return null;
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