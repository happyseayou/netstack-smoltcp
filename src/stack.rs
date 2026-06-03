use std::{
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use smoltcp::wire::IpProtocol;
use tokio::sync::mpsc::{channel, Receiver};
use tokio_util::sync::PollSender;
use tracing::{debug, trace};

use crate::{
    filter::{IpFilter, IpFilters},
    packet::{AnyIpPktFrame, IpPacket},
    runner::Runner,
    tcp::TcpListener,
    udp::UdpSocket,
};

pub struct StackBuilder {
    enable_udp: bool,
    enable_tcp: bool,
    enable_icmp: bool,
    mtu: usize,
    stack_buffer_size: usize,
    udp_buffer_size: usize,
    tcp_buffer_size: usize,
    ip_filters: IpFilters<'static>,
}

impl Default for StackBuilder {
    fn default() -> Self {
        Self {
            enable_udp: false,
            enable_tcp: false,
            enable_icmp: false,
            mtu: 1504,
            stack_buffer_size: 1024,
            udp_buffer_size: 512,
            tcp_buffer_size: 512,
            ip_filters: IpFilters::with_non_broadcast(),
        }
    }
}

#[allow(unused)]
impl StackBuilder {
    pub fn enable_udp(mut self, enable: bool) -> Self {
        self.enable_udp = enable;
        self
    }

    pub fn enable_tcp(mut self, enable: bool) -> Self {
        self.enable_tcp = enable;
        self
    }

    pub fn enable_icmp(mut self, enable: bool) -> Self {
        self.enable_icmp = enable;
        self
    }

    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    pub fn stack_buffer_size(mut self, size: usize) -> Self {
        self.stack_buffer_size = size;
        self
    }

    pub fn udp_buffer_size(mut self, size: usize) -> Self {
        self.udp_buffer_size = size;
        self
    }

    pub fn tcp_buffer_size(mut self, size: usize) -> Self {
        self.tcp_buffer_size = size;
        self
    }

    pub fn set_ip_filters(mut self, filters: IpFilters<'static>) -> Self {
        self.ip_filters = filters;
        self
    }

    pub fn add_ip_filter(mut self, filter: IpFilter<'static>) -> Self {
        self.ip_filters.add(filter);
        self
    }

    pub fn add_ip_filter_fn<F>(mut self, filter: F) -> Self
    where
        F: Fn(&IpAddr, &IpAddr) -> bool + Send + Sync + 'static,
    {
        self.ip_filters.add_fn(filter);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn build(
        self,
    ) -> std::io::Result<(
        Stack,
        Option<Runner>,
        Option<UdpSocket>,
        Option<TcpListener>,
    )> {
        let (stack_tx, stack_rx) = channel(self.stack_buffer_size);

        let (udp_tx, udp_rx) = if self.enable_udp {
            let (udp_tx, udp_rx) = channel(self.udp_buffer_size);
            (Some(udp_tx), Some(udp_rx))
        } else {
            (None, None)
        };

        let (tcp_tx, tcp_rx) = if self.enable_tcp {
            let (tcp_tx, tcp_rx) = channel(self.tcp_buffer_size);
            (Some(tcp_tx), Some(tcp_rx))
        } else {
            (None, None)
        };

        // ICMP is handled by TCP's Interface.
        // smoltcp's interface will always send replies to EchoRequest
        if self.enable_icmp && !self.enable_tcp {
            use std::io::{Error, ErrorKind::InvalidInput};
            return Err(Error::new(InvalidInput, "ICMP requires TCP"));
        }
        let icmp_tx = if self.enable_icmp {
            tcp_tx.clone()
        } else {
            None
        };

        let udp_socket = udp_rx.map(|udp_rx| UdpSocket::new(udp_rx, stack_tx.clone()));

        let (tcp_runner, tcp_listener) = if let Some(tcp_rx) = tcp_rx {
            let (tcp_runner, tcp_listener) = TcpListener::new(tcp_rx, stack_tx, self.mtu)?;
            (Some(tcp_runner), Some(tcp_listener))
        } else {
            (None, None)
        };

        let stack = Stack {
            ip_filters: self.ip_filters,
            stack_rx,
            sink_buf: None,
            udp_tx: udp_tx.map(PollSender::new),
            tcp_tx: tcp_tx.map(PollSender::new),
            icmp_tx: icmp_tx.map(PollSender::new),
        };

        Ok((stack, tcp_runner, udp_socket, tcp_listener))
    }
}

pub struct Stack {
    ip_filters: IpFilters<'static>,
    sink_buf: Option<(AnyIpPktFrame, IpProtocol)>,
    udp_tx: Option<PollSender<AnyIpPktFrame>>,
    tcp_tx: Option<PollSender<AnyIpPktFrame>>,
    icmp_tx: Option<PollSender<AnyIpPktFrame>>,
    stack_rx: Receiver<AnyIpPktFrame>,
}

impl Stack {
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let (item, proto) = match self.sink_buf.take() {
            Some(val) => val,
            None => return Poll::Ready(Ok(())),
        };

        let sender = match proto {
            IpProtocol::Tcp => self.tcp_tx.as_mut(),
            IpProtocol::Udp => self.udp_tx.as_mut(),
            IpProtocol::Icmp | IpProtocol::Icmpv6 => self.icmp_tx.as_mut(),
            _ => unreachable!(),
        };

        let Some(sender) = sender else {
            return Poll::Ready(Ok(()));
        };

        match sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(channel_closed_err("channel is closed"))),
            Poll::Pending => {
                self.sink_buf.replace((item, proto));
                return Poll::Pending;
            }
        }

        if sender.send_item(item).is_err() {
            return Poll::Ready(Err(channel_closed_err("channel is closed")));
        }

        Poll::Ready(Ok(()))
    }
}

// Recv from stack.
impl Stream for Stack {
    type Item = std::io::Result<AnyIpPktFrame>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.stack_rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Send to stack.
impl Sink<AnyIpPktFrame> for Stack {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.sink_buf.is_some() {
            self.poll_send(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: AnyIpPktFrame) -> Result<(), Self::Error> {
        if item.is_empty() {
            return Ok(());
        }

        use std::io::{Error, ErrorKind::InvalidInput};
        let packet = IpPacket::new_checked(item.as_slice())
            .map_err(|err| Error::new(InvalidInput, format!("invalid IP packet: {err}")))?;

        let src_ip = packet.src_addr();
        let dst_ip = packet.dst_addr();

        let addr_allowed = self.ip_filters.is_allowed(&src_ip, &dst_ip);
        if !addr_allowed {
            trace!("IP packet {src_ip} -> {dst_ip} (allowed? {addr_allowed}) throwing away",);
            return Ok(());
        }

        let protocol = packet.protocol();
        if matches!(
            protocol,
            IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Icmp | IpProtocol::Icmpv6
        ) {
            self.sink_buf.replace((item, protocol));
        } else {
            debug!("tun IP packet ignored (protocol: {:?})", protocol);
        }

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_send(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.stack_rx.close();
        Poll::Ready(Ok(()))
    }
}

fn channel_closed_err<E>(err: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, err)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        time::Duration,
    };

    use etherparse::PacketBuilder;
    use futures::{SinkExt, StreamExt};
    use tokio::time::{sleep, timeout};

    use super::*;

    #[tokio::test]
    async fn stack_sink_wakes_after_protocol_channel_has_capacity() {
        let (stack, _runner, udp_socket, _tcp_listener) = StackBuilder::default()
            .enable_udp(true)
            .udp_buffer_size(1)
            .build()
            .expect("build stack");
        let udp_socket = udp_socket.expect("udp socket");
        let (mut stack_sink, _stack_stream) = stack.split();
        let (mut udp_read, _udp_write) = udp_socket.split();

        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1111));
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2222));
        let first = udp_ipv4_packet(local, remote, b"first");
        let second = udp_ipv4_packet(local, remote, b"second");

        stack_sink.send(first).await.expect("first packet");
        let second_send = tokio::spawn(async move { stack_sink.send(second).await });

        sleep(Duration::from_millis(50)).await;
        assert!(
            !second_send.is_finished(),
            "second send should wait while UDP channel is full"
        );

        let (payload, observed_local, observed_remote) =
            udp_read.next().await.expect("first udp packet");
        assert_eq!(payload, b"first");
        assert_eq!(observed_local, local);
        assert_eq!(observed_remote, remote);

        timeout(Duration::from_secs(1), second_send)
            .await
            .expect("second send should be woken after capacity returns")
            .expect("second send task")
            .expect("second packet");

        let (payload, observed_local, observed_remote) =
            udp_read.next().await.expect("second udp packet");
        assert_eq!(payload, b"second");
        assert_eq!(observed_local, local);
        assert_eq!(observed_remote, remote);
    }

    fn udp_ipv4_packet(local: SocketAddr, remote: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (SocketAddr::V4(local), SocketAddr::V4(remote)) = (local, remote) else {
            unreachable!("test uses IPv4 only");
        };
        let builder = PacketBuilder::ipv4(local.ip().octets(), remote.ip().octets(), 20)
            .udp(local.port(), remote.port());
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).expect("udp packet");
        packet
    }
}
