include!(concat!(env!("OUT_DIR"), "/hadoop.hdfs.rs"));

pub mod datanode {
    include!(concat!(env!("OUT_DIR"), "/hadoop.hdfs.datanode.rs"));
}

pub mod namenode {
    include!(concat!(env!("OUT_DIR"), "/hadoop.hdfs.namenode.rs"));
}
