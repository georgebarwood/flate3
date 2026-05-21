use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::io::Cursor;

fn load_input() -> Vec<u8> {
    let path = std::env::var("BENCH_INPUT").unwrap_or_else(|_| "enwik8".to_string());
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!("cannot read {path}: {e}. Set BENCH_INPUT=<path> or place enwik8-20m in repo root.")
    })
}

fn ratio(input_len: usize, output_len: usize) -> f64 {
    input_len as f64 / output_len as f64
}

fn compress_bench(c: &mut Criterion) {
    let data = load_input();
    let input_len = data.len();

    let mut group = c.benchmark_group("compress");
    group.throughput(Throughput::Bytes(input_len as u64));

    let flate3_out = flate3::deflate(&data);
    assert_eq!(flate3::inflate(&flate3_out), data);
    group.bench_function(
        format!("flate3 [ratio={:.2}x]", ratio(input_len, flate3_out.len())),
        |b| b.iter(|| flate3::deflate(&data)),
    );

    let lz4_out = lz4_flex::compress_prepend_size(&data);
    group.bench_function(
        format!(
            "lz4_flex [ratio={:.2}x]",
            ratio(input_len, lz4_out.len())
        ),
        |b| b.iter(|| lz4_flex::compress_prepend_size(&data)),
    );

    let zstd1_out = zstd::encode_all(Cursor::new(&data), 1).unwrap();
    group.bench_function(
        format!(
            "zstd level-1 [ratio={:.2}x]",
            ratio(input_len, zstd1_out.len())
        ),
        |b| b.iter(|| zstd::encode_all(Cursor::new(&data), 1).unwrap()),
    );

    let zstd3_out = zstd::encode_all(Cursor::new(&data), 3).unwrap();
    group.bench_function(
        format!(
            "zstd level-3 [ratio={:.2}x]",
            ratio(input_len, zstd3_out.len())
        ),
        |b| b.iter(|| zstd::encode_all(Cursor::new(&data), 3).unwrap()),
    );

    let flate2_out = {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(&data).unwrap();
        e.finish().unwrap()
    };
    group.bench_function(
        format!(
            "flate2 [ratio={:.2}x]",
            ratio(input_len, flate2_out.len())
        ),
        |b| {
            b.iter(|| {
                use flate2::write::DeflateEncoder;
                use flate2::Compression;
                use std::io::Write;
                let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
                e.write_all(&data).unwrap();
                e.finish().unwrap()
            })
        },
    );

    let miniz_out =
        miniz_oxide::deflate::compress_to_vec(&data, 6);
    group.bench_function(
        format!(
            "miniz_oxide [ratio={:.2}x]",
            ratio(input_len, miniz_out.len())
        ),
        |b| b.iter(|| miniz_oxide::deflate::compress_to_vec(&data, 6)),
    );

    group.finish();
}

fn decompress_bench(c: &mut Criterion) {
    let data = load_input();
    let input_len = data.len();

    let flate3_compressed = flate3::deflate(&data);
    let lz4_compressed = lz4_flex::compress_prepend_size(&data);
    let zstd1_compressed = zstd::encode_all(Cursor::new(&data), 1).unwrap();
    let zstd3_compressed = zstd::encode_all(Cursor::new(&data), 3).unwrap();
    let flate2_compressed = {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(&data).unwrap();
        e.finish().unwrap()
    };
    let miniz_compressed = miniz_oxide::deflate::compress_to_vec(&data, 6);

    let mut group = c.benchmark_group("decompress");
    group.throughput(Throughput::Bytes(input_len as u64));

    group.bench_function("flate3", |b| {
        b.iter(|| flate3::inflate(&flate3_compressed))
    });

    group.bench_function("lz4_flex", |b| {
        b.iter(|| lz4_flex::decompress_size_prepended(&lz4_compressed).unwrap())
    });

    group.bench_function("zstd (from level-1)", |b| {
        b.iter(|| zstd::decode_all(Cursor::new(&zstd1_compressed)).unwrap())
    });

    group.bench_function("zstd (from level-3)", |b| {
        b.iter(|| zstd::decode_all(Cursor::new(&zstd3_compressed)).unwrap())
    });

    group.bench_function("flate2", |b| {
        b.iter(|| {
            use flate2::read::DeflateDecoder;
            use std::io::Read;
            let mut decoder = DeflateDecoder::new(&flate2_compressed[..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).unwrap();
            out
        })
    });

    group.bench_function("miniz_oxide", |b| {
        b.iter(|| miniz_oxide::inflate::decompress_to_vec(&miniz_compressed).unwrap())
    });

    group.finish();
}

criterion_group!(benches, compress_bench, decompress_bench);
criterion_main!(benches);
