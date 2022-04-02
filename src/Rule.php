<?php

namespace Azurre\Iptables;

/**
 * Class Rule
 *
 * @property int $num
 * @property string $target
 * @property string $protocol
 * @property string $source
 * @property string $in
 * @property string $out
 * @property string $destination
 * @property array $options
 */
class Rule
{
    use PropertyAccessTrait;

    /** @var int */
    private $num;

    /** @var string */
    private $target;

    /** @var int */
    private $protocol = 'all';

    /** @var string */
    private $source = '0.0.0.0/0';

    /** @var string */
    private $in = '*';

    /** @var string */
    private $out = '*';

    /** @var string */
    private $destination = '0.0.0.0/0';

    /** @var array */
    private $options = [];

    /** @var array */
    private static $significantProps = ['target', 'protocol', 'source', 'in', 'out', 'destination', 'options'];

    const PROTOCOLS = [47 => 'gre'];

    /**
     * Rule constructor.
     * @param null|string $target
     * @param null|int $protocol
     * @param null|string $source
     * @param null|string $destination
     * @param null|string|array $options
     */
    public function __construct($target = null, $protocol = null, $source = null, $destination = null, $options = null)
    {
        $this->target = $target ?: $this->target;
        $this->protocol = $protocol ?: $this->protocol;
        $this->source = $source ?: $this->source;
        $this->destination = $destination ?: $this->destination;
        $this->setOptions($options ?: $this->options);
    }

    /**
     * @param array|\ArrayAccess $rule
     * @return static
     */
    public static function create($rule)
    {
        $instance = new static();
        foreach ($rule as $key => $value) {
            if (property_exists($instance, $key)) {
                $instance->__set($key, $value);
            }
        }
        return $instance;
    }

    /**
     * @return array
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     * @return string
     */
    public function getDestination()
    {
        return $this->destination;
    }

    /**
     * @return string
     */
    public function getSource()
    {
        return $this->source;
    }

    /**
     * @return string
     */
    public function getProtocol()
    {
        return $this->protocol;
    }

    /**
     * @return string
     */
    public function getTarget()
    {
        return $this->target;
    }

    /**
     * @return int
     */
    public function getNum()
    {
        return $this->num;
    }

    /**
     * @return array
     */
    public function dump(){
      return [
        'num'=>$this->num,
        'target'=>$this->target,
        'protocol'=>$this->protocol,
        'source'=>$this->source,
        'destination'=>$this->destination,
        'options'=>$this->options,
      ];
    }

    /**
     * @param int $num
     */
    public function setNum($num)
    {
        $this->num = $num;
    }

    /**
     * @param array|string $options
     * @return $this
     */
    public function setOptions($options)
    {
        if (is_array($options)) {
            $this->options = $options;
        } else {
            $this->parseOptions($options);
        }

        return $this;
    }

    /**
     * @param bool $convertToName
     * @return string
     */
    public function getProtocol($convertToName = true)
    {
        if ($convertToName && is_numeric($this->protocol)) {
            return static::PROTOCOLS[$this->protocol] ?: $this->protocol;
        }
        return $this->protocol;
    }

    /**
     * @param string $options
     */
    private function parseOptions($options)
    {
        $options = trim($options);
        if (empty($options)) {
            $this->options = [];
            return;
        }
        // find if any port options has been set
        if (preg_match('/(?:(?<direction>([sd])pt)s?:)(?<exclude>!?)(?<ports>(\d+):?(\d+))/', $options, $parsed)) {
            $map = ['dpt' => '--destination-port', 'spt' => '--source-port'];
            $excl = !empty($parsed['exclude']) ? $parsed['exclude'] . ' ' : '';
            $this->options[$map[$parsed['direction']]] = $excl . $parsed['ports'];
        }

        // find if --mach mac has been set
        if (preg_match_all('/MAC\s(?<macaddress>[\d:]+)/', $options, $parsed)) {
            for ($i = 0; $i < count($parsed['macaddress']); $i++) {
                $this->options['--match'][] = 'mac --mac-source ' . $parsed['macaddress'][$i];
            }
        }

        // find if limit has been set
        if (preg_match_all('/limit:\savg\s(?<limit>\d+\/(sec|min|hour|day))\sburst\s(?<burst>\d+)/', $options, $parsed)) {
            for ($i = 0; $i < count($parsed['limit']); $i++) {
                $this->options['--match'][] = 'limit --limit ' . $parsed['limit'][$i] . ' --limit-burst ' . $parsed['burst'][$i];
            }
        }
    }

    /**
     * @return string
     */
    public function __toString()
    {
        $cmd = '';

        if ('all' != $this->protocol) {
            $cmd .= ' --proto ' . $this->protocol;
        }
        if (!is_null($this->source) && '0.0.0.0/0' != $this->source) {
            $cmd .= ' --source ' . $this->source;
        }
        if (!is_null($this->destination) && '0.0.0.0/0' != $this->destination) {
            $cmd .= ' --destination ' . $this->destination;
        }
        if ($this->in && $this->in !== '*') {
            $cmd .= ' --in-interface ' . $this->in;
        }
        if ($this->out && $this->out !== '*') {
            $cmd .= ' --out-interface ' . $this->out;
        }

        foreach ($this->options as $k => $value) {
            if (is_scalar($value)) {
                $cmd .= ' ' . $k . ' ' . $value;
            } else {
                foreach ($value as $option) {
                    $cmd .= ' ' . $k . ' ' . $option;
                }
            }
        }

        $cmd .= !empty($this->target) ? ' --jump ' . $this->target : '';

        return $cmd;
    }

    /**
     * @param Rule $rule
     * @return bool
     */
    public function isEqualTo(Rule $rule)
    {
        foreach (static::$significantProps as $key) {
            if ($this->{$key} !== $rule->{$key}) {
                return false;
            }
        }
        return true;
    }
}