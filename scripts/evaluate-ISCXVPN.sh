# this script finetunes a model on a test dataset
# Use GPU 0 (change to 1,2,3,4,5,6 if needed - avoid 7 which is occupied)
export CUDA_VISIBLE_DEVICES=1

    # --train_dir /home/ronghua/codes/IoTdataset/CICIoT2023/final/shards \
    # --train_dir /home/ronghua/codes/netFound/data/ISCVPN2016/final/shards \
python src/train/NetfoundEvaluate.py \
  --train_dir /home/ronghua/codes/netFound/data/ISCVPN2016/attack_remove/final/shards \
  --model_name_or_path /home/ronghua/codes/netFound/models/ISCXVPN_finetuned2/checkpoint-18040 \
  --output_dir /home/ronghua/codes/netFound/models/ISCXVPN_finetuned2/eval_attack_remove \
  --report_to tensorboard \
  --save_safetensors false \
  --problem_type single_label_classification \
  --netfound_large True\
  --num_labels 6