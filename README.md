# XDP-DEV
Um repositorio onde vou postar alguns programas e fazer alguns comentarios sobre, com intuito de compartilhar a minha jornada.

## O que eu sei?

### 12/12/2023
Tenho um conhecimento basico sobre o que é XDP e o que é o eBPF.

Basicamente, o eBPF é uma ferramenta para realizar e trabalhar com sys-calls do kernel, ou seja, trabalhar no baixo nivel do kernel.

XDP? Bom, xdp é o caminho expresso de dados, onde os dados chegam, então você consegue trabalhar com os pacotes de rede diretamente e com uma alta velocidade.

### prog1
É uma aplicação XDP, que busca "brincar" com ataques TCP Syn... a minha primeira aplicação eBPF usando a seção XDP

### 28/01/2025
Se passou um longo tempo desde a ultima atualização, Porém, não de outros projetos...

Bom, esse tempo eu estudei estruturas e mais coisa sobre varias stacks, principalmente sobre o desenvolvimento com eBPF.

Pude aproveitar e finalmente colocar meus conhecimentos com o eBPF em pratica em uma empresa surgindo com meus amigos, a TrustEdge.

Nesse projeto, atualmente me foi passada a função de manter e atualizar um filtro legado, com filtro de aplicações especificas e varios protocolos.
O filtro estava usando uma versão antiga e depreciada do LIBBPF, então a primeira coisa que eu fiz foi atualizar ela e junto fazer um loader em C++, que carrega e atualiza as regras de firewall de acordo com os comandos passados a ele.

Uma outra tarefa importante, foi o redirecionamento de pacotes UDP relacionados com "Query" de algumas aplicações para servidores proxy. para fazer isso, eu utilizei um truque do proprio XDP e um mapa.
Primeiramente eu armazeno as informações de um servidor proxy, como IP, Porta, Endereço MAC e o tipo de aplicação que ele vai responder. Feito isso, quando um pacote query chega no firewall eu pego o pacote, altero o endereço mac de destino, endereço IP de destino do pacote, e também a porta no cabeçalho UDP ( não esquecendo de recalcular o checksum ), agora vem a magica... é só usar a xdp_action XDP_TX, que faz o pacote ser retransmitido. Dessa forma eu redireciono o pacote ao proxy, que vai fazer seu travalho de responder o cliente.

```c

void* data;
void* data_end;
struct ethhdr* eth;
struct iphdr* iph;
struct udphdr* udph;
// Trocando as informações para o endereço do proxy desejado
static __always_inline int proxy_redirect(struct ethhdr *eth, struct iphdr *iph, struct udphdr *udph, void *data_end, uint8_t type)
{
    __u32 key = type;
    struct proxy_info *proxy = bpf_map_lookup_elem(&proxy_list, &key);
    if (proxy == NULL)
    {
        return -1;
    }

    memcpy(eth->h_dest, proxy->mac, ETH_ALEN);
    iph->daddr = proxy->ip;
    udph->dest = proxy->port;
    udph->check = calc_udp_csum(iph, udph, data_end);
    return 1;
}

proxy_redirect(eth, iph, udph, data_end, type);
return XDP_TX;
```

