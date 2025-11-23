#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help"
    echo "  -d, --debug         Собрать Debug версию (по умолчанию)"
    echo "  -r, --release       Build Release version"
    echo "  -b, --both          Build both versions (Debug and Release)"
    echo "  -c, --clean         Clean build directories before compilation"
    echo "  -i, --install       Install after build (requires sudo for Release)"
    echo "  -e, --examples      Build examples"
    echo "  -z, --no-zlib       Disable zlib support"
    echo "  -s, --no-openssl    Disable OpenSSL support"
    echo "  -t, --strip         Remove symbols from Release build (strip)"
    echo "  -j, --jobs N        Number of parallel build tasks (default: all available cores)"
    echo ""
    echo "Примеры:"
    echo "  $0 -d                    # Build Debug version"
    echo "  $0 -r                    # Build Release version"
    echo "  $0 -b                    # Build both versions"
    echo "  $0 -r -i -t              # Build, install and remove symbols from Release"
    echo "  $0 -b -e                 # Build both versions with examples"
    echo "  $0 -c -r                 # Clean and build Release version"
}

BUILD_DEBUG=false
BUILD_RELEASE=false
CLEAN_BUILD=false
INSTALL_BUILD=false
BUILD_EXAMPLES=false
WITH_ZLIB=ON
WITH_OPENSSL=OFF
STRIP_SYMBOLS=false
PARALLEL_JOBS=$(nproc 2>/dev/null || echo 4)

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--debug)
            BUILD_DEBUG=true
            shift
            ;;
        -r|--release)
            BUILD_RELEASE=true
            shift
            ;;
        -b|--both)
            BUILD_DEBUG=true
            BUILD_RELEASE=true
            shift
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -i|--install)
            INSTALL_BUILD=true
            shift
            ;;
        -e|--examples)
            BUILD_EXAMPLES=true
            shift
            ;;
        -z|--no-zlib)
            WITH_ZLIB=OFF
            shift
            ;;
        -s|--no-openssl)
            WITH_OPENSSL=OFF
            shift
            ;;
        -t|--strip)
            STRIP_SYMBOLS=true
            shift
            ;;
        -j|--jobs)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        *)
            error "Unknown parameter: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ "$BUILD_DEBUG" = false ] && [ "$BUILD_RELEASE" = false ]; then
    BUILD_DEBUG=true
fi

clean_build_dir() {
    local build_dir=$1
    if [ -d "$build_dir" ]; then
        info "Clean dir $build_dir..."
        rm -rf "$build_dir"
        success "Dir $build_dir cleaned"
    fi
}

build_project() {
    local build_type=$1
    local build_dir="build_${build_type,,}"
    
    info "Build ${build_type} version..."
    
    if [ "$CLEAN_BUILD" = true ]; then
        clean_build_dir "$build_dir"
    fi
    
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    local cmake_args=(
        -DCMAKE_BUILD_TYPE="$build_type"
        -DOVERPROTO_WITH_ZLIB="$WITH_ZLIB"
        -DOVERPROTO_WITH_OPENSSL="$WITH_OPENSSL"
        -DOVERPROTO_BUILD_EXAMPLES="$BUILD_EXAMPLES"
    )
    

    if [ "$build_type" = "Release" ] && [ "$STRIP_SYMBOLS" = true ]; then
        cmake_args+=(-DOVERPROTO_STRIP_SYMBOLS=ON)
    fi
    
    info "Configure CMake..."
    cmake "${cmake_args[@]}" ..

    info "Compile (using $PARALLEL_JOBS parallel tasks)..."
    cmake --build . --parallel "$PARALLEL_JOBS"
    
    if [ "$INSTALL_BUILD" = true ]; then
        info "Install..."
        if [ "$build_type" = "Release" ]; then
            sudo cmake --install .
        else
            cmake --install .
        fi
        success "Install completed"
    fi
    
    cd ..
    success "${build_type} build completed! (dir: $build_dir)"
}

main() {
    info "OverProto build script"
    info "Build parameters:"
    info "  - Debug: $BUILD_DEBUG"
    info "  - Release: $BUILD_RELEASE"
    info "  - Clean: $CLEAN_BUILD"
    info "  - Install: $INSTALL_BUILD"
    info "  - Examples: $BUILD_EXAMPLES"
    info "  - zlib: $WITH_ZLIB"
    info "  - OpenSSL: $WITH_OPENSSL"
    info "  - Strip: $STRIP_SYMBOLS"
    info "  - Parallel tasks: $PARALLEL_JOBS"
    echo ""
    
    if ! command -v cmake &> /dev/null; then
        error "CMake not found! Install CMake before using the script."
        exit 1
    fi
    
    if [ "$BUILD_DEBUG" = true ]; then
        build_project "Debug"
        echo ""
    fi
    
    if [ "$BUILD_RELEASE" = true ]; then
        build_project "Release"
        echo ""
    fi
    
    success "All builds completed successfully!"
    
    echo ""
    info "Build results:"
    if [ "$BUILD_DEBUG" = true ]; then
        if [ -f "build_debug/liboverproto.a" ]; then
            local size=$(du -h build_debug/liboverproto.a | cut -f1)
            info "  - Debug library: build_debug/liboverproto.a ($size)"
        fi
        if [ "$BUILD_EXAMPLES" = true ]; then
            if [ -f "build_debug/overproto_client" ]; then
                info "  - Debug client: build_debug/overproto_client"
            fi
            if [ -f "build_debug/overproto_server" ]; then
                info "  - Debug server: build_debug/overproto_server"
            fi
        fi
    fi
    
    if [ "$BUILD_RELEASE" = true ]; then
        if [ -f "build_release/liboverproto.a" ]; then
            local size=$(du -h build_release/liboverproto.a | cut -f1)
            info "  - Release library: build_release/liboverproto.a ($size)"
        fi
        if [ "$BUILD_EXAMPLES" = true ]; then
            if [ -f "build_release/overproto_client" ]; then
                info "  - Release client: build_release/overproto_client"
            fi
            if [ -f "build_release/overproto_server" ]; then
                info "  - Release server: build_release/overproto_server"
            fi
        fi
    fi
}

main

