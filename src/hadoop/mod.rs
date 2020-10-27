pub mod common {
    include!(concat!(env!("OUT_DIR"), "/hadoop.common.rs"));
}

pub mod hdfs;
