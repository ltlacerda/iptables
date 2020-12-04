<?php
namespace azurre\iptables;

/**
 * Class Rule
 */
class Rule
{
    /** @var int */
    private $num;

    /** @var string */
    private $target;

    /** @var int */
    private $protocol;

    /** @var string */
    private $source;

    /** @var string */
    private $in;

    /** @var string */
    private $out;

    /** @var string */
    private $destination;

    /** @var array */
    private $options = [];

    /**
     * Rule constructor.
     * @param string $target
     * @param int $protocol
     * @param string $source
     * @param string $destination
     * @param string|array $options
     */
    public function __construct($target = null, $protocol = null, $source = null, $destination = null, $options = [])
    {
        $this->target = $target;
        $this->protocol = $protocol;
        $this->source = $source;
        $this->destination = $destination;

        if (is_array($options)) {
            $this->options = $options;
        } else {
            $this->parseOptions($options);
        }
    }

    /**
     * @param array|\ArrayAccess $rule
     * @return static
     */
    public static function create($rule)
    {
        $instance = new static();
        foreach ($rule as $key => $value) {
            if ($value && property_exists($instance, $key)) {
                $instance->{$key} = $value;
            }
        }
        if (!is_array($instance->options)) {
            $instance->parseOptions((string)$instance->options);
        }
        return $instance;
    }

    /**
     * @return int
     */
    public function getNum()
    {
        return $this->num;
    }

    /**
     * @param int $num
     */
    public function setNum($num)
    {
        $this->num = $num;
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
}