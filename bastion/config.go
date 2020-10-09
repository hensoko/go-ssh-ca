package bastion

type Config struct {
	Upstreams []Upstream `json:"upstreams"`
}
