//
// Copyright (c) 2022 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

use std::fmt::Display;

use cyclors::qos::Qos;
use zenoh::key_expr::OwnedKeyExpr;

use crate::{config::Config, node_info::*, ros2_utils::key_expr_to_ros2_name};

/// A (local) discovery event of a ROS2 interface
#[derive(Debug)]
pub enum ROS2DiscoveryEvent {
    DiscoveredMsgPub(String, MsgPub),
    UndiscoveredMsgPub(String, MsgPub),
    DiscoveredMsgSub(String, MsgSub),
    UndiscoveredMsgSub(String, MsgSub),
    DiscoveredServiceSrv(String, ServiceSrv),
    UndiscoveredServiceSrv(String, ServiceSrv),
    DiscoveredServiceCli(String, ServiceCli),
    UndiscoveredServiceCli(String, ServiceCli),
    DiscoveredActionSrv(String, ActionSrv),
    UndiscoveredActionSrv(String, ActionSrv),
    DiscoveredActionCli(String, ActionCli),
    UndiscoveredActionCli(String, ActionCli),
}

impl std::fmt::Display for ROS2DiscoveryEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ROS2DiscoveryEvent::*;
        match self {
            DiscoveredMsgPub(node, iface) => write!(f, "Node {node} declares {iface}"),
            DiscoveredMsgSub(node, iface) => write!(f, "Node {node} declares {iface}"),
            DiscoveredServiceSrv(node, iface) => write!(f, "Node {node} declares {iface}"),
            DiscoveredServiceCli(node, iface) => write!(f, "Node {node} declares {iface}"),
            DiscoveredActionSrv(node, iface) => write!(f, "Node {node} declares {iface}"),
            DiscoveredActionCli(node, iface) => write!(f, "Node {node} declares {iface}"),
            UndiscoveredMsgPub(node, iface) => write!(f, "Node {node} undeclares {iface}"),
            UndiscoveredMsgSub(node, iface) => write!(f, "Node {node} undeclares {iface}"),
            UndiscoveredServiceSrv(node, iface) => write!(f, "Node {node} undeclares {iface}"),
            UndiscoveredServiceCli(node, iface) => write!(f, "Node {node} undeclares {iface}"),
            UndiscoveredActionSrv(node, iface) => write!(f, "Node {node} undeclares {iface}"),
            UndiscoveredActionCli(node, iface) => write!(f, "Node {node} undeclares {iface}"),
        }
    }
}

impl ROS2DiscoveryEvent {
    pub(crate) fn is_allowed(&self, config: &Config) -> bool {
        if let Some(allowance) = &config.allowance {
            use ROS2DiscoveryEvent::*;
            match self {
                DiscoveredMsgPub(node, iface) | UndiscoveredMsgPub(node, iface) => {
                    // Open question: now that a Publisher (or any interface type) can match the allow/deny rule
                    // either by the topic name or either by the node name, what shall be the rules ?
                    //
                    // E.g. for a Publisher on "/t" from a node "N", is it allowed with:
                    // - 'allow: { publishers: ["/t"], nodes: ["X"] }' ?  YES since "/t" is allowed, but NO since "N" is not allowed ?
                    // - 'allow: { publishers: ["/x"], nodes: ["N"] }' ?  YES since "N" is allowed, but NO since "/t" is not allowed ?
                    // - 'deny: { publishers: ["/t"], nodes: ["X"] }' ?   NO since "/t" is denied, but YES since "N" is not denied ?
                    // - 'deny: { publishers: ["/x"], nodes: ["N"] }' ?   NO since "N" is denied, but YES since "/t" is not denied ?

                    if allowance.is_allow_by_default() {
                        allowance.is_node_allowed(node)
                            && allowance.is_publisher_allowed(&iface.name)
                    } else {
                        allowance.is_node_allowed(node)
                            || allowance.is_publisher_allowed(&iface.name)
                    }
                }
                DiscoveredMsgSub(node, iface) | UndiscoveredMsgSub(node, iface) => {
                    if allowance.is_allow_by_default() {
                        allowance.is_node_allowed(node)
                            && allowance.is_subscriber_allowed(&iface.name)
                    } else {
                        allowance.is_node_allowed(node)
                            || allowance.is_subscriber_allowed(&iface.name)
                    }
                }
                DiscoveredServiceSrv(node, iface) | UndiscoveredServiceSrv(node, iface) => {
                    if allowance.is_allow_by_default() {
                        allowance.is_node_allowed(node)
                            && allowance.is_service_srv_allowed(&iface.name)
                    } else {
                        allowance.is_node_allowed(node)
                            || allowance.is_service_srv_allowed(&iface.name)
                    }
                }
                DiscoveredServiceCli(node, iface) | UndiscoveredServiceCli(node, iface) => {
                    if allowance.is_allow_by_default() {
                        allowance.is_node_allowed(node)
                            && allowance.is_service_cli_allowed(&iface.name)
                    } else {
                        allowance.is_node_allowed(node)
                            || allowance.is_service_cli_allowed(&iface.name)
                    }
                }
                DiscoveredActionSrv(node, iface) | UndiscoveredActionSrv(node, iface) => {
                    if allowance.is_allow_by_default() {
                        allowance.is_node_allowed(node)
                            && allowance.is_action_srv_allowed(&iface.name)
                    } else {
                        allowance.is_node_allowed(node)
                            || allowance.is_action_srv_allowed(&iface.name)
                    }
                }
                DiscoveredActionCli(node, iface) | UndiscoveredActionCli(node, iface) => {
                    if allowance.is_allow_by_default() {
                        allowance.is_node_allowed(node)
                            && allowance.is_action_cli_allowed(&iface.name)
                    } else {
                        allowance.is_node_allowed(node)
                            || allowance.is_action_cli_allowed(&iface.name)
                    }
                }
            }
        } else {
            // no allow/deny configured => allow all
            true
        }
    }
}

/// A (remote) announcement/retirement of a ROS2 interface
#[derive(Debug)]
pub enum ROS2AnnouncementEvent {
    AnnouncedMsgPub {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
        ros2_type: String,
        keyless: bool,
        writer_qos: Qos,
    },
    RetiredMsgPub {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
    },
    AnnouncedMsgSub {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
        ros2_type: String,
        keyless: bool,
        reader_qos: Qos,
    },
    RetiredMsgSub {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
    },
    AnnouncedServiceSrv {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
        ros2_type: String,
    },
    RetiredServiceSrv {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
    },
    AnnouncedServiceCli {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
        ros2_type: String,
    },
    RetiredServiceCli {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
    },
    AnnouncedActionSrv {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
        ros2_type: String,
    },
    RetiredActionSrv {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
    },
    AnnouncedActionCli {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
        ros2_type: String,
    },
    RetiredActionCli {
        zenoh_id: OwnedKeyExpr,
        zenoh_key_expr: OwnedKeyExpr,
    },
}

impl Display for ROS2AnnouncementEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ROS2AnnouncementEvent::*;
        match self {
            AnnouncedMsgPub { zenoh_key_expr, .. } => {
                write!(f, "announces Publisher {zenoh_key_expr}")
            }
            AnnouncedMsgSub { zenoh_key_expr, .. } => {
                write!(f, "announces Subscriber {zenoh_key_expr}")
            }
            AnnouncedServiceSrv { zenoh_key_expr, .. } => {
                write!(f, "announces Service Server {zenoh_key_expr}")
            }
            AnnouncedServiceCli { zenoh_key_expr, .. } => {
                write!(f, "announces Service Client {zenoh_key_expr}")
            }
            AnnouncedActionSrv { zenoh_key_expr, .. } => {
                write!(f, "announces Action Server {zenoh_key_expr}")
            }
            AnnouncedActionCli { zenoh_key_expr, .. } => {
                write!(f, "announces Action Client {zenoh_key_expr}")
            }
            RetiredMsgPub { zenoh_key_expr, .. } => write!(f, "retires Publisher {zenoh_key_expr}"),
            RetiredMsgSub { zenoh_key_expr, .. } => {
                write!(f, "retires Subscriber {zenoh_key_expr}")
            }
            RetiredServiceSrv { zenoh_key_expr, .. } => {
                write!(f, "retires Service Server {zenoh_key_expr}")
            }
            RetiredServiceCli { zenoh_key_expr, .. } => {
                write!(f, "retires Service Client {zenoh_key_expr}")
            }
            RetiredActionSrv { zenoh_key_expr, .. } => {
                write!(f, "retires Action Server {zenoh_key_expr}")
            }
            RetiredActionCli { zenoh_key_expr, .. } => {
                write!(f, "retires Action Client {zenoh_key_expr}")
            }
        }
    }
}

impl ROS2AnnouncementEvent {
    // Check if a remote announcement by another bridge is allowed, depending on the matching entity allowance in config.
    // E.g. a remote announcement of a Publisher on /abc is allowed only if a Subscriber on /abc is allowed in the local config.
    pub(crate) fn is_allowed(&self, config: &Config) -> bool {
        if let Some(allowance) = &config.allowance {
            // TODO: deal with "nodes" allow/deny rules
            use ROS2AnnouncementEvent::*;
            match self {
                AnnouncedMsgPub { zenoh_key_expr, .. } | RetiredMsgPub { zenoh_key_expr, .. } => {
                    allowance.is_subscriber_allowed(&key_expr_to_ros2_name(zenoh_key_expr, config))
                }
                AnnouncedMsgSub { zenoh_key_expr, .. } | RetiredMsgSub { zenoh_key_expr, .. } => {
                    allowance.is_publisher_allowed(&key_expr_to_ros2_name(zenoh_key_expr, config))
                }
                AnnouncedServiceSrv { zenoh_key_expr, .. }
                | RetiredServiceSrv { zenoh_key_expr, .. } => {
                    allowance.is_service_cli_allowed(&key_expr_to_ros2_name(zenoh_key_expr, config))
                }
                AnnouncedServiceCli { zenoh_key_expr, .. }
                | RetiredServiceCli { zenoh_key_expr, .. } => {
                    allowance.is_service_srv_allowed(&key_expr_to_ros2_name(zenoh_key_expr, config))
                }
                AnnouncedActionSrv { zenoh_key_expr, .. }
                | RetiredActionSrv { zenoh_key_expr, .. } => {
                    allowance.is_action_cli_allowed(&key_expr_to_ros2_name(zenoh_key_expr, config))
                }
                AnnouncedActionCli { zenoh_key_expr, .. }
                | RetiredActionCli { zenoh_key_expr, .. } => {
                    allowance.is_action_srv_allowed(&key_expr_to_ros2_name(zenoh_key_expr, config))
                }
            }
        } else {
            // no allow/deny configured => allow all
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{config::Config, events::*};

    #[test]
    fn test_discovery_events_allowance() {
        use super::ROS2DiscoveryEvent::*;

        let allowed_local_pub = MsgPub {
            name: "/pub".into(),
            typ: "T".into(),
            writers: HashSet::default(),
        };
        let allowed_local_sub = MsgSub {
            name: "/sub".into(),
            typ: "T".into(),
            readers: HashSet::default(),
        };
        let allowed_local_srv_srv = ServiceSrv {
            name: "/srv_srv".into(),
            typ: "T".into(),
            entities: ServiceSrvEntities::default(),
        };
        let allowed_local_srv_cli = ServiceCli {
            name: "/srv_cli".into(),
            typ: "T".into(),
            entities: ServiceCliEntities::default(),
        };
        let allowed_local_act_srv = ActionSrv {
            name: "/act_srv".into(),
            typ: "T".into(),
            entities: ActionSrvEntities::default(),
        };
        let allowed_local_act_cli = ActionCli {
            name: "/act_cli".into(),
            typ: "T".into(),
            entities: ActionCliEntities::default(),
        };

        let denied_local_pub = MsgPub {
            name: "/XXX_pub".into(),
            typ: "T".into(),
            writers: HashSet::default(),
        };
        let denied_local_sub = MsgSub {
            name: "/XXX_sub".into(),
            typ: "T".into(),
            readers: HashSet::default(),
        };
        let denied_local_srv_srv = ServiceSrv {
            name: "/XXX_srv_srv".into(),
            typ: "T".into(),
            entities: ServiceSrvEntities::default(),
        };
        let denied_local_srv_cli = ServiceCli {
            name: "/XXX_srv_cli".into(),
            typ: "T".into(),
            entities: ServiceCliEntities::default(),
        };
        let denied_local_act_srv = ActionSrv {
            name: "/XXX_act_srv".into(),
            typ: "T".into(),
            entities: ActionSrvEntities::default(),
        };
        let denied_local_act_cli = ActionCli {
            name: "/XXX_act_cli".into(),
            typ: "T".into(),
            entities: ActionCliEntities::default(),
        };

        let config: Config = serde_json::from_str(
            r#"{
              "allow": {
                "publishers": ["/pub"],
                "subscribers": ["/sub"],
                "service_servers": ["/srv_srv"],
                "service_clients": ["/srv_cli"],
                "action_servers": ["/act_srv"],
                "action_clients": ["/act_cli"],
                "nodes": ["allowed_node"]
              }
            }"#,
        )
        .unwrap();

        assert!(
            DiscoveredMsgPub("allowed_node".into(), allowed_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredMsgPub("allowed_node".into(), denied_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredMsgPub("denied_node".into(), allowed_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgPub("denied_node".into(), denied_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredMsgSub("allowed_node".into(), allowed_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredMsgSub("allowed_node".into(), denied_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredMsgSub("denied_node".into(), allowed_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgSub("denied_node".into(), denied_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredServiceSrv("allowed_node".into(), allowed_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredServiceSrv("allowed_node".into(), denied_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredServiceSrv("denied_node".into(), allowed_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceSrv("denied_node".into(), denied_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredServiceCli("allowed_node".into(), allowed_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredServiceCli("allowed_node".into(), denied_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredServiceCli("denied_node".into(), allowed_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceCli("denied_node".into(), denied_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionSrv("allowed_node".into(), allowed_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionSrv("allowed_node".into(), denied_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionSrv("denied_node".into(), allowed_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionSrv("denied_node".into(), denied_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionCli("allowed_node".into(), allowed_local_act_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionCli("allowed_node".into(), denied_local_act_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionCli("denied_node".into(), allowed_local_act_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionCli("denied_node".into(), denied_local_act_cli.clone())
                .is_allowed(&config)
        );

        let config: Config = serde_json::from_str(
            r#"{
              "deny": {
                "publishers": ["/XXX_pub"],
                "subscribers": ["/XXX_sub"],
                "service_servers": ["/XXX_srv_srv"],
                "service_clients": ["/XXX_srv_cli"],
                "action_servers": ["/XXX_act_srv"],
                "action_clients": ["/XXX_act_cli"],
                "nodes": ["denied_node"]
              }
            }"#,
        )
        .unwrap();

        assert!(
            DiscoveredMsgPub("allowed_node".into(), allowed_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgPub("allowed_node".into(), denied_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgPub("denied_node".into(), allowed_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgPub("denied_node".into(), denied_local_pub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredMsgSub("allowed_node".into(), allowed_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgSub("allowed_node".into(), denied_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgSub("denied_node".into(), allowed_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            !DiscoveredMsgSub("denied_node".into(), denied_local_sub.clone()).is_allowed(&config)
        );
        assert!(
            DiscoveredServiceSrv("allowed_node".into(), allowed_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceSrv("allowed_node".into(), denied_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceSrv("denied_node".into(), allowed_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceSrv("denied_node".into(), denied_local_srv_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredServiceCli("allowed_node".into(), allowed_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceCli("allowed_node".into(), denied_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceCli("denied_node".into(), allowed_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredServiceCli("denied_node".into(), denied_local_srv_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionSrv("allowed_node".into(), allowed_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionSrv("allowed_node".into(), denied_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionSrv("denied_node".into(), allowed_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionSrv("denied_node".into(), denied_local_act_srv.clone())
                .is_allowed(&config)
        );
        assert!(
            DiscoveredActionCli("allowed_node".into(), allowed_local_act_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionCli("allowed_node".into(), denied_local_act_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionCli("denied_node".into(), allowed_local_act_cli.clone())
                .is_allowed(&config)
        );
        assert!(
            !DiscoveredActionCli("denied_node".into(), denied_local_act_cli.clone())
                .is_allowed(&config)
        );
    }


    fn test_announcement_events_allowance() {
        use super::ROS2AnnouncementEvent::*;

        // TODO...
    }

}
