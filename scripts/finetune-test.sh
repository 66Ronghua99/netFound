# this script finetunes a model on a test dataset
# Use GPU 0 (change to 1,2,3,4,5,6 if needed - avoid 7 which is occupied)
export CUDA_VISIBLE_DEVICES=0

    # --train_dir /home/ronghua/codes/IoTdataset/CICIoT2023/final/shards \
    # --train_dir /home/ronghua/codes/netFound/data/ISCVPN2016/final/shards \
python \
    src/train/NetfoundFinetuning.py \
    --train_dir /home/ronghua/codes/IoTdataset/CICIoT2023/final/shards \
    --model_name_or_path models/pretrained_model \
    --output_dir models/CICIoT_finetuned4 \
    --report_to tensorboard \
    --overwrite_output_dir \
    --save_safetensors false \
    --do_train \
    --do_eval \
    --eval_strategy epoch \
    --save_strategy epoch \
    --learning_rate 1e-5 \
    --num_train_epochs 10 \
    --problem_type single_label_classification \
    --num_labels 5 \
    --load_best_model_at_end \
    --netfound_large True\
    --overwrite_output_dir


